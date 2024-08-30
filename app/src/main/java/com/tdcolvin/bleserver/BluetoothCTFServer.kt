package com.tdcolvin.bleserver

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.content.pm.PackageManager
import android.os.ParcelUuid
import android.util.Log
import android.widget.Toast
import androidx.annotation.RequiresPermission
import androidx.core.app.ActivityCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

const val CTF_SERVICE_UUID = "8c380000-10bd-4fdb-ba21-1922d6cf860d"
const val PASSWORD_CHARACTERISTIC_UUID = "8c380001-10bd-4fdb-ba21-1922d6cf860d"
const val NAME_CHARACTERISTIC_UUID = "8c380002-10bd-4fdb-ba21-1922d6cf860d"

//These fields are marked as API >= 31 in the Manifest class, so we can't use those without warning.
//So we create our own, which prevents over-suppression of the Linter
const val PERMISSION_BLUETOOTH_ADVERTISE = "android.permission.BLUETOOTH_ADVERTISE"
const val PERMISSION_BLUETOOTH_CONNECT = "android.permission.BLUETOOTH_CONNECT"

class BluetoothCTFServer(private val context: Context) {
    private val bluetooth = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? BluetoothManager
        ?: throw Exception("This device doesn't support Bluetooth")

    private val serviceUuid = UUID.fromString(CTF_SERVICE_UUID)
    private val passwordCharUuid = UUID.fromString(PASSWORD_CHARACTERISTIC_UUID)
    private val nameCharUuid = UUID.fromString(NAME_CHARACTERISTIC_UUID)

    private var server: BluetoothGattServer? = null
    private var ctfService: BluetoothGattService? = null

    private var advertiseCallback: AdvertiseCallback? = null
    private val isServerListening: MutableStateFlow<Boolean?> = MutableStateFlow(null)

    private val preparedWrites = HashMap<Int, ByteArray>()

    val namesReceived = MutableStateFlow(emptyList<String>())

    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_CONNECT, PERMISSION_BLUETOOTH_ADVERTISE])
    suspend fun startServer() = withContext(Dispatchers.IO) {
        //If server already exists, we don't need to create one
        if (server != null) {
            return@withContext
        }

        startAdvertising()
        startHandlingIncomingConnections()

    }

    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_CONNECT, PERMISSION_BLUETOOTH_ADVERTISE])
    suspend fun stopServer() = withContext(Dispatchers.IO) {
        //if no server, nothing to do
        if (server == null) {
            return@withContext
        }

        stopAdvertising()
        stopHandlingIncomingConnections()
    }

    @SuppressLint("MissingPermission")
    @RequiresPermission(PERMISSION_BLUETOOTH_ADVERTISE)
    private suspend fun startAdvertising() {
        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        val bluetoothAdapter = bluetoothManager.adapter
        bluetoothAdapter.name = "TEST"

        val advertiser: BluetoothLeAdvertiser = bluetooth.adapter.bluetoothLeAdvertiser
            ?: throw Exception("This device is not able to advertise")

        //if already advertising, ignore
        if (advertiseCallback != null) {
            return
        }

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_BALANCED)
            .setConnectable(true)
            .setTimeout(0)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)

            .build()

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(BluetoothAdapter.getDefaultAdapter().setName("TEST"))
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid(serviceUuid))
//            .addServiceData(ParcelUuid(serviceUuid), "Data")
            .build()

        advertiseCallback = suspendCoroutine { continuation ->
            val advertiseCallback = object: AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    Toast.makeText(context, "Advertising 성공~ ", Toast.LENGTH_SHORT).show()

                    super.onStartSuccess(settingsInEffect)

                    continuation.resume(this)
                }

                override fun onStartFailure(errorCode: Int) {
                    super.onStartFailure(errorCode)
                    throw Exception("Unable to start advertising, errorCode: $errorCode")
                }
            }
            advertiser.startAdvertising(settings, data, advertiseCallback)
        }
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_ADVERTISE)
    private fun stopAdvertising() {
        val advertiser: BluetoothLeAdvertiser = bluetooth.adapter.bluetoothLeAdvertiser
            ?: throw Exception("This device is not able to advertise")

        //if not currently advertising, ignore
        advertiseCallback?.let {
            advertiser.stopAdvertising(it)
            advertiseCallback = null
        }
    }

    private fun startHandlingIncomingConnections() {
        if (ActivityCompat.checkSelfPermission(
                context,
                Manifest.permission.BLUETOOTH_CONNECT
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            Log.v("bluetooth", "startHandlingIncomingConnections failed")
            return
        }
        Log.v("bluetooth", "startHandlingIncomingConnections success")

        server = bluetooth.openGattServer(context, object: BluetoothGattServerCallback() {
            override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
                super.onServiceAdded(status, service)
                Log.v("bluetooth server status", status.toString())
                Log.v("bluetooth onServiceAdded", service?.includedServices.toString())
                isServerListening.value = true
            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic?
            ) {
                super.onCharacteristicReadRequest(device, requestId, offset, characteristic)


                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, "HELLO".encodeToByteArray())
            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicWriteRequest(
                device: BluetoothDevice,
                requestId: Int,
                characteristic: BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray
            ) {
                super.onCharacteristicWriteRequest(
                    device,
                    requestId,
                    characteristic,
                    preparedWrite,
                    responseNeeded,
                    offset,
                    value
                )
                super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)

                if(preparedWrite) {
                    val bytes = preparedWrites.getOrDefault(requestId, byteArrayOf())
                    preparedWrites[requestId] = bytes.plus(value)
                }
                else {
                    namesReceived.update { it.plus(String(value)) }
                }

                if(responseNeeded) {
                    server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf())
                }
            }

            override fun onExecuteWrite(
                device: BluetoothDevice?,
                requestId: Int,
                execute: Boolean
            ) {
                super.onExecuteWrite(device, requestId, execute)
                val bytes = preparedWrites.remove(requestId)
                if (execute && bytes != null) {
                    namesReceived.update { it.plus(String(bytes)) }
                }
            }
        })

        if (server == null) {
            Log.w("bluetooth server", "Unable to create GATT server")
        } else {
            Log.v("bluetooth server", "Enable to create GATT server")

        }
        val service = BluetoothGattService(serviceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)

        val passwordCharacteristic = BluetoothGattCharacteristic(
            passwordCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )

        val nameCharacteristic = BluetoothGattCharacteristic(
            nameCharUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        service.addCharacteristic(passwordCharacteristic)
        service.addCharacteristic(nameCharacteristic)
        Log.v("bluetooth server", "addService")

        server?.addService(service)
        Log.v("bluetooth server", server?.services.toString())
        ctfService = service
    }

    @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
    private fun stopHandlingIncomingConnections() {
        ctfService?.let {
            server?.removeService(it)
            ctfService = null
        }
    }
}