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
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
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

    var publicKey: PublicKey? = null
    private var privateKey: PrivateKey? = null
    private var receivePublicKey: PublicKey? = null

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
                Log.d("TTTT", characteristic!!.uuid.toString())

                if (characteristic != null) {
                    if (characteristic.uuid == publicKeyCharUuid) {
                        generateKeyPair().apply {
                            publicKey = this.first
                            privateKey = this.second
                        }

                        Log.d("TTTT public key :", publicKeyToString(publicKey!!))
                        Log.d("TTTT privateKey key :", priveKeyToString(privateKey!!))

                        val data = publicKey!!.encoded

                        server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data)
                    }
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
                Log.d("TTTT", "onCharacteristicWriteRequest")
                Log.d("TTTT", characteristic.uuid.toString())
                Log.d("TTTT data", dataCharUuid.toString())

                if (characteristic.uuid.equals(publicKeyCharUuid)) {
                    Log.d("TTTT value : ", publicKeyToString(getPublicKeyFromEncoded(value)))
                    receivePublicKey = getPublicKeyFromEncoded(value)
                    if(preparedWrite) {
                        val bytes = preparedWrites.getOrDefault(requestId, byteArrayOf())
                        preparedWrites[requestId] = bytes.plus(value)
                    }
                    else {
                        namesReceived.update { it.plus(publicKeyToString(getPublicKeyFromEncoded(value))) }
                    }

                    if(responseNeeded) {
                        server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf())
                    }

                } else if (characteristic.uuid.equals(dataCharUuid)) {
                    val sharedSecret = generateSharedSecret(privateKey!!, receivePublicKey!!)

                    Log.d("TTTT encrypt value : ", String(value))
                    Log.d("TTTT decrypt value : ", String(decrypt(value, sharedSecret)))

                }

            }

            override fun onMtuChanged(device: BluetoothDevice?, mtu: Int) {
                super.onMtuChanged(device, mtu)
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
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )

        val dataCharacteristic = BluetoothGattCharacteristic(
            dataCharUuid,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
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
    }

    fun stringToJson(jsonString: String): JSONObject {
        return JSONObject(jsonString)
    }

    fun publicKeyToString(publicKey: PublicKey): String {
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    fun priveKeyToString(privateKey: PrivateKey): String {
        return Base64.getEncoder().encodeToString(privateKey.encoded)
    }

    fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(256)
        val keyPair = keyGen.generateKeyPair()
        return Pair(keyPair.public, keyPair.private)
    }

    fun generateSharedSecret(privateKey: PrivateKey, publicKey: PublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        return keyAgreement.generateSecret()
    }

    // AES-256 암호화
    fun encrypt(data: ByteArray, secret: ByteArray): ByteArray {
        val key: SecretKey = SecretKeySpec(secret.copyOf(32), "AES") // 32 bytes for AES-256
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(16).apply { java.security.SecureRandom().nextBytes(this) } // 랜덤 IV 생성
        val ivParameterSpec = IvParameterSpec(iv)

        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec)
        val encrypted = cipher.doFinal(data)

        // IV와 암호문을 Base64로 인코딩하여 반환
        return iv + encrypted
    }

    // AES-256 복호화
    fun decrypt(encryptedData: ByteArray, secret: ByteArray): ByteArray {
        val key: SecretKey = SecretKeySpec(secret.copyOf(32), "AES")
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        val iv = encryptedData.copyOfRange(0, 16) // IV를 추출
        val encryptedBytes = encryptedData.copyOfRange(16, encryptedData.size)

        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec)
        return cipher.doFinal(encryptedBytes)
    }

    fun getPublicKeyFromEncoded(encoded: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(encoded)
        val keyFactory = KeyFactory.getInstance("EC") // ECDH 알고리즘 사용
        return keyFactory.generatePublic(keySpec)
    }

}