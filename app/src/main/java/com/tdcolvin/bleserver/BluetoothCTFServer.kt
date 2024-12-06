package com.tdcolvin.bleserver

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
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
import org.json.JSONObject
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
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
    private val TAG = "TTTT"
    var sharedSecretKey: ByteArray? = null
    private var clientOffset = 0
    private var mtuSize = 23  // MTU 크기 설정 (최대 크기 확인 필요)
    private val END_OF_DATA = "END_OF_DATA"  // 데이터 끝을 알리는 마커 (문자열로 설정)
    // 각 클라이언트의 MAC 주소를 사용하여 오프셋 관리
    private var fullData = byteArrayOf()  // 전체 데이터를 받을 StringBuilder
    private var serverOffset = 0

    // 예시로 전송할 데이터
    private val data2 = "abcdef1안녕하세요호호2안녕하세요호호3안녕하세요호호4안녕하세요호호5안녕하세요호호6안녕하세요호호7안녕하세요호호8안녕하세요호호9안녕하세요호호10안녕하세요호호11안녕하세요호호12안녕하세요호호13안녕하세요호호14안녕하세요호호15안녕하세요호호16안녕하세요호호17안녕하세요호호18안녕하세요호호19안녕하세요호호20안녕하세요호호21안녕하세요호호22안녕하세요호호23안녕하세요호호24안녕하세요호호25안녕하세요호호26안녕하세요호호27안녕하세요호호28안녕하세요호호29안녕하세요호호30안녕하세요호호31안녕하세요호호32안녕하세요호호33안녕하세요호호34안녕하세요호호35안녕하세요호호36안녕하세요호호37안녕하세요호호38안녕하세요호호39안녕하세요호호40안녕하세요호호41안녕하세요호호42안녕하세요호호43안녕하세요호호44안녕하세요호호45안녕하세요호호46안녕하세요호호47안녕하세요호호48안녕하세요호호49안녕하세요호호50안녕하세요호호51안녕하세요호호52안녕하세요호호53안녕하세요호호54END_OF_DATA"

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
                Log.d("TTTT","onDescriptorWriteRequest")
            }

            override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
                super.onNotificationSent(device, status)
                Log.d("TTTT" , "onNotificationSent")
            }

            override fun onConnectionStateChange(
                device: BluetoothDevice?,
                status: Int,
                newState: Int
            ) {
                super.onConnectionStateChange(device, status, newState)

                Log.d("TTTT" , "onConnectionStateChange")
                Log.d("TTTT" , "$device, $status, $newState")


            }

            override fun onDescriptorReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                descriptor: BluetoothGattDescriptor?
            ) {
                super.onDescriptorReadRequest(device, requestId, offset, descriptor)
                Log.d("TTTT" , "onDescriptorReadRequest")

            }

            override fun onPhyRead(device: BluetoothDevice?, txPhy: Int, rxPhy: Int, status: Int) {
                super.onPhyRead(device, txPhy, rxPhy, status)
                Log.d("TTTT" , "onPhyRead")

            }

            override fun onPhyUpdate(
                device: BluetoothDevice?,
                txPhy: Int,
                rxPhy: Int,
                status: Int
            ) {
                super.onPhyUpdate(device, txPhy, rxPhy, status)
                Log.d("TTTT" , "onPhyUpdate")

            }

            @RequiresPermission(PERMISSION_BLUETOOTH_CONNECT)
            override fun onCharacteristicReadRequest(
                device: BluetoothDevice?,
                requestId: Int,
                offset: Int,
                characteristic: BluetoothGattCharacteristic?
            ) {
                super.onCharacteristicReadRequest(device, requestId, offset, characteristic)
                Log.d("TTTT", "onCharacteristicReadRequest")
                Log.d("TTTT uuid", characteristic!!.uuid.toString())
                Log.d("TTTT device", "$device")
                Log.d("TTTT requestId", requestId.toString())

                /**
                 * @brief publicKey Test
                 */
//                if (publicKey == null) {
//                    return
//                }
//
//                if (characteristic != null) {
//                    if (characteristic.uuid == publicKeyCharUuid) {
//                        Log.d("TTTT public key :", publicKeyToString(publicKey!!))
//                        Log.d("TTTT privateKey key :", priveKeyToString(privateKey!!))
//
//                        val data = sendData(publicKey!!)
//
//                        server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, data)
//                    }
//                }
//                val data = "안녕하세요1안녕하세요2안녕하세요3안녕하세요4안녕하세요5안녕하세요6안녕하세요7안녕하세요8안녕하세요9안녕하세요10안녕하세요11안녕하세요12안녕하세요13안녕하세요14안녕하세요15안녕하세요16안녕하세요17안녕하세요18안녕하세요19안녕하세요20안녕하세요21안녕하세요22안녕하세요23안녕하세요24안녕하세요25안녕하세요26안녕하세요27안녕하세요28안녕하세요29안녕하세요30안녕하세요31안녕하세요32안녕하세요33안녕하세요34안녕하세요35안녕하세요36안녕하세요37안녕하세요38안녕하세요39안녕하세요40안녕하세요41안녕하세요42안녕하세요43안녕하세요44안녕하세요45안녕하세요46안녕하세요47안녕하세요48안녕하세요49안녕하세요50안녕하세요51안녕하세요52안녕하세요53안녕하세요54END_OF_DATA"
//                Log.d("TTTT data:", data)
//                val chunkSize = mtuSize - 3
//                Log.d("TTTT chunk", chunkSize.toString())
//
//                val chunks = data.chunked(chunkSize)
//                for (chunk in chunks) {
//                    Log.d("TTTT chunk :", chunk)
//
//                    val byteData = chunk.toByteArray()
//                    server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, byteData)
//
//                }

                //
                // 특성 값이 너무 크면 데이터를 MTU 크기만큼 나누어 전송
                val dataBytes = data2.toByteArray(Charset.forName("UTF-8"))
                Log.d("BLE Server mtuSize", mtuSize.toString())

                // MTU 크기 계산 (오버헤드를 고려하여 실제 데이터 전송 크기 계산)
                val mtuSize = mtuSize - 3 // 헤더 크기 등 고려
                // 요청된 오프셋에 해당하는 데이터 범위 계산
                val endOffset = minOf(clientOffset + mtuSize, dataBytes.size)
                Log.d("BLE Server offset", clientOffset.toString())
                Log.d("BLE Server endOffset", endOffset.toString())

                if (clientOffset < dataBytes.size) {
                    val dataChunk = dataBytes.copyOfRange(clientOffset, endOffset)
                    Log.d("BLE Server", "Sending data chunk: ${String(dataChunk)}")

                    // 클라이언트에 데이터 전송
                    server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, clientOffset, dataChunk)
                    clientOffset = endOffset - 2
                    // 데이터가 아직 남아 있다면, 이어서 요청을 처리
                    if (endOffset < dataBytes.size) {
                        Log.d("BLE Server", "Remaining data, waiting for next read request")
                    } else {
                        characteristic.value = ByteArray(0x00)

                        server?.notifyCharacteristicChanged(
                            device,  // 클라이언트 디바이스 주소
                            characteristic,
                            false,  // 인디케이션이 아니므로 false,
                        )
                        Log.d("BLE Server", "Data transmission complete.")
                    }
                } else {
                    // 요청된 offset이 데이터 범위를 벗어나면 오류 응답
                    server?.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, clientOffset, null)
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
                Log.d("TTTT", "onCharacteristicWriteRequest")
                Log.d("TTTT", characteristic.uuid.toString())
                Log.d("TTTT byte data :", "byte = ${value.contentToString()}")
                Log.d("TTTT data :", "String = ${android.util.Base64.encode(value, android.util.Base64.NO_WRAP).decodeToString()}")
//                Log.d("TTTT size: ", value.size.toString())
//                if (value.size < 64) {
//                    return
//
//                }
//                Log.d("TTTT offest :", offset.toString())
//
//                val ecParameterSpec: ECParameterSpec = KeyFactory
//                    .getInstance("EC")
//                    .getKeySpec(
//                        publicKey,
//                        ECPublicKeySpec::class.java
//                    ).params
//
//                if (characteristic.uuid.equals(publicKeyCharUuid)) {
//                    Log.d("TTTT value : ", publicKeyToString(getEcPublicKey(value, ecParameterSpec)))
//                    receivePublicKey = getEcPublicKey(value, ecParameterSpec)
//
//                    sharedSecretKey = generateSharedSecret(privateKey!!, receivePublicKey!!)
//                    Log.d("TTTT secret byte : ", sharedSecretKey!!.decodeToString())
//                    Log.d("TTTT secret content byte : ", sharedSecretKey.contentToString())
//                    Log.d("TTTT secret base64 :", "String = ${android.util.Base64.encode(sharedSecretKey, android.util.Base64.NO_WRAP).decodeToString()}")
//
//                    if(preparedWrite) {
//                        val bytes = preparedWrites.getOrDefault(requestId, byteArrayOf())
//                        preparedWrites[requestId] = bytes.plus(value)
//                    }
//                    else {
//                        namesReceived.update { it.plus(publicKeyToString(getEcPublicKey(value, ecParameterSpec))) }
//                    }
//
//                    if(responseNeeded) {
//                        server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf())
//                    }
//
//                } else if (characteristic.uuid.equals(dataCharUuid)) {
//                    Log.d("TTTT encrypt value : ", String(value))
//                    Log.d("TTTT decrypt value : ", String(decrypt(value, sharedSecretKey!!)))
//
//                }

                val data = value

                // 받은 데이터를 문자열로 변환
                val receivedData = data
                Log.d("TTTT byteSize", receivedData.size.toString())

                // 데이터를 StringBuilder에 추가
                fullData += receivedData

                val strReceivedData = String(receivedData)
                Log.d("BluetoothGattClient", "Received chunk: $strReceivedData")

                // 받은 데이터가 "END_OF_DATA"인지 확인
                if (String(receivedData).contains("END_OF_DATA")) {
                    // "END_OF_DATA"가 포함되었다면, 데이터 수신 완료
                    val hexString = fullData.joinToString(" ") { String.format("%02X", it) }
                    Log.d("Complete Byte Data:", "ByteArray: $hexString")
                    Log.d("Complete Data:", String(fullData))
                    // 여기서 받은 데이터를 처리합니다.
                } else {
                    // 아직 끝나지 않은 경우, 다음 데이터를 읽기 위해 offset을 증가시키고 다시 요청
                    serverOffset += mtuSize
                }

                characteristic.value = byteArrayOf(0x00)
                server?.notifyCharacteristicChanged(
                    device,  // 클라이언트 디바이스 주소
                    characteristic,
                    false,  // 인디케이션이 아니므로 false,
                )
//                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, clientOffset, ByteArray(0x00))

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

    private fun sendData(publicKey: PublicKey): ByteArray? {
        if (publicKey is ECPublicKey) {
            val ecPublicKey = publicKey as ECPublicKey
            val affineXByteArray = ecPublicKey.w.affineX.toByteArray()
            val filteredAffineXByteArray = filterMostSignificantByte(affineXByteArray)
            val affineYByteArray = ecPublicKey.w.affineY.toByteArray()
            val filteredAffineYByteArray = filterMostSignificantByte(affineYByteArray)
            val keyByteArray = byteArrayOf(0x04).plus(filteredAffineXByteArray).plus(filteredAffineYByteArray)
            Log.d(TAG, "ECPublicKey affineXByteArray = ${affineXByteArray.contentToString()}, size = ${affineXByteArray.size}")
            Log.d(TAG, "ECPublicKey affineYByteArray = ${affineYByteArray.contentToString()}, size = ${affineYByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineXByteArray = ${filteredAffineXByteArray.contentToString()}, size = ${filteredAffineXByteArray.size}")
            Log.d(TAG, "ECPublicKey filteredAffineYByteArray = ${filteredAffineYByteArray.contentToString()}, size = ${filteredAffineYByteArray.size}")
            Log.d(TAG, "ECPublicKey keyByteArray = ${keyByteArray.contentToString()}, size = ${keyByteArray.size}")

            return keyByteArray
        } else {
            Log.d(TAG, "ECPublicKey This is not an EC public key.")
        }
        return null
    }

    private fun filterMostSignificantByte(byteArray: ByteArray): ByteArray {
        val xBytes32 = ByteArray(32)
        val byteArraySize = byteArray.size
        Log.d(TAG, "filterMostSignificantByte byteArray = ${byteArray.decodeToString()}, byteArraySize = $byteArraySize")

        if (byteArraySize <= 32) {
            // 패딩 추가
            System.arraycopy(byteArray, 0, xBytes32, 32 - byteArraySize, byteArraySize)
        } else if (byteArraySize == 33) {
            // 33바이트인 경우, 최상위 바이트 제거
            System.arraycopy(byteArray, 1, xBytes32, 0, 32)
        } else {
            throw Throwable("removeMostSignificantByte Too many Byte")
        }

        return xBytes32
    }

    private fun generateKeyPair(): Pair<PublicKey, PrivateKey> {
        val keyGen = KeyPairGenerator.getInstance("EC")
        keyGen.initialize(ECGenParameterSpec("secp256r1")) // P-256은 secp256r1로 정의됨
        val keyPair = keyGen.generateKeyPair()
        return Pair(keyPair.public, keyPair.private)
    }

    private fun getEcPublicKey(ecPublicKey: ByteArray, params: ECParameterSpec): PublicKey {
        val ecPointX = ecPublicKey.sliceArray(IntRange(1, 32))
        val ecPointY = ecPublicKey.sliceArray(IntRange(33, 64))
        // x와 y를 BigInteger로 변환
        val x = BigInteger(1, ecPointX) // 1은 부호를 나타냄 (양수)
        val y = BigInteger(1, ecPointY)

        // ECPoint를 사용하여 공개 키의 포인트 정의
        val ecPoint = ECPoint(x, y)
        val keyFactory = KeyFactory.getInstance("EC") // ECDH 알고리즘 사용
        val pubSpec = ECPublicKeySpec(ecPoint, params)
        return keyFactory.generatePublic(pubSpec)

    }

}