package com.tdcolvin.bleserver

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
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
const val PUBLICK_KEY_DATA_CHARACTERISTIC_UUID = "8c380001-10bd-4fdb-ba21-1922d6cf860d"
const val DATA_CHARACTERISTIC_UUID = "8c380002-10bd-4fdb-ba21-1922d6cf860d"

//These fields are marked as API >= 31 in the Manifest class, so we can't use those without warning.
//So we create our own, which prevents over-suppression of the Linter
const val PERMISSION_BLUETOOTH_ADVERTISE = "android.permission.BLUETOOTH_ADVERTISE"
const val PERMISSION_BLUETOOTH_CONNECT = "android.permission.BLUETOOTH_CONNECT"

class BluetoothCTFServer(private val context: Context) {
    private val bluetooth = context.getSystemService(Context.BLUETOOTH_SERVICE)
            as? BluetoothManager
        ?: throw Exception("This device doesn't support Bluetooth")

    private val serviceUuid = UUID.fromString(CTF_SERVICE_UUID)
    private val publicKeyCharUuid = UUID.fromString(PUBLICK_KEY_DATA_CHARACTERISTIC_UUID)
    private val dataCharUuid = UUID.fromString(DATA_CHARACTERISTIC_UUID)

    private var server: BluetoothGattServer? = null
    private var ctfService: BluetoothGattService? = null

    private var advertiseCallback: AdvertiseCallback? = null
    private val isServerListening: MutableStateFlow<Boolean?> = MutableStateFlow(null)

    private val preparedWrites = HashMap<Int, ByteArray>()

    val namesReceived = MutableStateFlow(emptyList<String>())

    private var mtuSize = 23  // MTU 크기 설정 (최대 크기 확인 필요)
    private val END_OF_DATA = "END_OF_DATA"  // 데이터 끝을 알리는 마커 (문자열로 설정)
    // 각 클라이언트의 MAC 주소를 사용하여 오프셋 관리
    private val TAG: String = BluetoothCTFServer::class.java.simpleName
    private var scenarioTest:ScenarioTest? = null
    var scenario = SCENARIO.SCENARIO_1

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
            .build()

        advertiseCallback = suspendCoroutine { continuation ->
            val advertiseCallback = object: AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                    Toast.makeText(context, "${scenario} "+"Advertising 성공~ ", Toast.LENGTH_SHORT).show()
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
                val functionName = "onServiceAdded"
                Log.d(TAG + functionName, "server status : $status.toString()")
                Log.d(TAG + functionName, "onServiceAdded : ${service?.includedServices.toString()}")

                isServerListening.value = true
            }

            override fun onDescriptorWriteRequest(
                device: BluetoothDevice?,
                requestId: Int,
                descriptor: BluetoothGattDescriptor?,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray?
            ) {
                super.onDescriptorWriteRequest(
                    device,
                    requestId,
                    descriptor,
                    preparedWrite,
                    responseNeeded,
                    offset,
                    value
                )
                val functionName = "onDescriptorWriteRequest"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "requestId : $requestId")
                Log.d(TAG + functionName, "descriptor : $descriptor")
                Log.d(TAG + functionName, "preparedWrite : $preparedWrite")
                Log.d(TAG + functionName, "responseNeeded : $responseNeeded")
                Log.d(TAG + functionName, "offset : $offset")
                Log.d(TAG + functionName, "value : $value")

            }

            override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
                super.onNotificationSent(device, status)
                val functionName = "onNotificationSent"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "status : $status")
            }

            override fun onConnectionStateChange(
                device: BluetoothDevice?,
                status: Int,
                newState: Int
            ) {
                super.onConnectionStateChange(device, status, newState)
                val functionName = "onConnectionStateChange"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "status : $status")
                Log.d(TAG + functionName, "newState : $newState")

            }

            override fun onDescriptorReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                descriptor: BluetoothGattDescriptor?
            ) {
                super.onDescriptorReadRequest(device, requestId, offset, descriptor)
                val functionName = "onDescriptorReadRequest"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "requestId : $requestId")
                Log.d(TAG + functionName, "offset : $offset")
                Log.d(TAG + functionName, "descriptor : $descriptor")

            }

            override fun onPhyRead(device: BluetoothDevice?, txPhy: Int, rxPhy: Int, status: Int) {
                super.onPhyRead(device, txPhy, rxPhy, status)
                val functionName = "onPhyRead"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "txPhy : $txPhy")
                Log.d(TAG + functionName, "rxPhy : $rxPhy")
                Log.d(TAG + functionName, "status : $status")

            }

            override fun onPhyUpdate(
                device: BluetoothDevice?,
                txPhy: Int,
                rxPhy: Int,
                status: Int
            ) {
                super.onPhyUpdate(device, txPhy, rxPhy, status)
                val functionName = "onPhyUpdate"
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "txPhy : $txPhy")
                Log.d(TAG + functionName, "rxPhy : $rxPhy")
                Log.d(TAG + functionName, "status : $status")

            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic?
            ) {
                super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
                val functionName = "onCharacteristicReadRequest"
                Log.d(TAG + functionName, "scenario : $scenario")
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "requestId : $requestId")
                Log.d(TAG + functionName, "offset : $offset")
                Log.d(TAG + functionName, "characteristic : ${characteristic}")

                if (scenarioTest == null) {
                    scenarioTest = ScenarioTest(server!!, mtuSize, scenario)

                }
                scenarioTest?.let {
                    scenarioTest?.senarioTest_onRead_request(device, requestId, characteristic)
                }

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
                super.onCharacteristicWriteRequest(device, requestId, characteristic, preparedWrite, responseNeeded, offset, value)
                val functionName = "onCharacteristicWriteRequest"
                Log.d(TAG + functionName, "scenario : $scenario")
                Log.d(TAG + functionName, "device : $device")
                Log.d(TAG + functionName, "requestId : $requestId")
                Log.d(TAG + functionName, "preparedWrite : $preparedWrite")
                Log.d(TAG + functionName, "responseNeeded : $responseNeeded")
                Log.d(TAG + functionName, "offset : $offset")
                Log.d(TAG + functionName, "value : $value")

                if (scenarioTest == null) {
                    scenarioTest = ScenarioTest(server!!, mtuSize, scenario)
                }

                scenarioTest?.let {
                    scenarioTest?.senarioTest_onWrite_request(device, requestId, characteristic, value)

                }

            }

            override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
                super.onMtuChanged(device, mtu)
                mtuSize = mtu
                // MTU 변경 처리
                Log.d("TTTT GATT Server", "MTU changed to: $mtu")

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

        val publicKeyCharacteristic = BluetoothGattCharacteristic(
            publicKeyCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE  or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        val dataCharacteristic = BluetoothGattCharacteristic(
            dataCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE  or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        service.addCharacteristic(publicKeyCharacteristic)
        service.addCharacteristic(dataCharacteristic)

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
        server = null
    }

}