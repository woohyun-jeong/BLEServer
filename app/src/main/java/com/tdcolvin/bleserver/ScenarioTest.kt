package com.tdcolvin.bleserver

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.util.Log
import java.nio.charset.Charset

enum class SCENARIO {
    SCENARIO_1,
    SCENARIO_2,
    SCENARIO_3,
    SCENARIO_4,
    SCENARIO_5,
    SCENARIO_6,
    SCENARIO_7,
    SCENARIO_8
}

class ScenarioTest(server: BluetoothGattServer, mtuSize: Int, scenario: SCENARIO) {
    private val TAG: String = ScenarioTest::class.java.simpleName
    val server = server
    val mtuSize = mtuSize
    var serverOffset = 0
    var scenario = scenario
    var fullData:ByteArray? = byteArrayOf()
    val data = "abcdef1안녕하세요호호2안녕하세요호호3안녕하세요호호4안녕하세요호호5안녕하세요호호6안녕하세요호호7안녕하세요호호8안녕하세요호호9안녕하세요호호10안녕하세요호호11안녕하세요호호12안녕하세요호호13안녕하세요호호14안녕하세요호호15안녕하세요호호16안녕하세요호호17안녕하세요호호18안녕하세요호호19안녕하세요호호20안녕하세요호호21안녕하세요호호22안녕하세요호호23안녕하세요호호24안녕하세요호호25안녕하세요호호26안녕하세요호호27안녕하세요호호28안녕하세요호호29안녕하세요호호30안녕하세요호호31안녕하세요호호32안녕하세요호호33안녕하세요호호34안녕하세요호호35안녕하세요호호36안녕하세요호호37안녕하세요호호38안녕하세요호호39안녕하세요호호40안녕하세요호호41안녕하세요호호42안녕하세요호호43안녕하세요호호44안녕하세요호호45안녕하세요호호46안녕하세요호호47안녕하세요호호48안녕하세요호호49안녕하세요호호50안녕하세요호호51안녕하세요호호52안녕하세요호호53안녕하세요호호54END_OF_DATA"

    @SuppressLint("MissingPermission")
    fun senarioTest1_write_request(device: BluetoothDevice,
                           requestId: Int,
                           characteristic: BluetoothGattCharacteristic,
                           value: ByteArray) {
        val functionName = "senarioTest1_write"
        fullData = fullData!! + value

        Log.d(TAG + functionName,"data String: ${String(value)}")
        // 받은 데이터가 "END_OF_DATA"인지 확인
        if (String(value).contains("END_OF_DATA")) {
            val hexString = fullData?.joinToString(" ") { String.format("%02X", it) }
            Log.d(TAG + functionName,"Complete Byte Data: ByteArray: $hexString")
            Log.d(TAG + functionName,"Complete Data: String: ${String(fullData!!)}")
            fullData = null
            fullData = byteArrayOf()
            server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf(0x06, 0x01, 0x01))
            serverOffset = 0
            if (scenario == SCENARIO.SCENARIO_2 ||
                scenario == SCENARIO.SCENARIO_3 ||
                scenario == SCENARIO.SCENARIO_4) {
                senarioTest2_notification(device, requestId, characteristic)
            }
        } else {
            // 아직 끝나지 않은 경우, 다음 데이터를 읽기 위해 offset을 증가시키고 다시 요청
            serverOffset += mtuSize
            characteristic.value = byteArrayOf(0x06)
            server.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, byteArrayOf(0x06, 0x01, 0x01))
        }

    }

    @SuppressLint("MissingPermission")
    fun senarioTest1_read_request(
        device: BluetoothDevice?,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic?

    ) {
        val functionName = "senarioTest1_read"

        Log.d(TAG + functionName, "uuid: ${characteristic!!.uuid.toString()}")
        Log.d(TAG + functionName, "device: ${device}")
        Log.d(TAG + functionName, "requestId: ${requestId.toString()}")

        // 특성 값이 너무 크면 데이터를 MTU 크기만큼 나누어 전송
        val dataBytes = data.toByteArray(Charset.forName("UTF-8"))
        Log.d(TAG + functionName,"mtuSize: ${mtuSize.toString()}")

        // MTU 크기 계산 (오버헤드를 고려하여 실제 데이터 전송 크기 계산)
        val mtuSize = mtuSize - 7 // 헤더 크기 등 고려
        // 요청된 오프셋에 해당하는 데이터 범위 계산
        val endOffset = minOf(serverOffset + mtuSize, dataBytes.size)
        Log.d(TAG + functionName,"offset: ${serverOffset.toString()}")
        Log.d(TAG + functionName,"endOffset: ${endOffset.toString()}")

        if (serverOffset < dataBytes.size) {
            val dataChunk = dataBytes.copyOfRange(serverOffset, endOffset)
            Log.d(TAG + functionName,"Sending data chunk: ${dataChunk.decodeToString()}")
            Log.d(TAG + functionName,"Sending data chunk size: ${dataChunk.size}")

            // 클라이언트에 데이터 전송
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, serverOffset, dataChunk)
            serverOffset = endOffset
            // 데이터가 아직 남아 있다면, 이어서 요청을 처리
            if (endOffset < dataBytes.size) {
                Log.d(TAG + functionName,"Remaining data, waiting for next read request")
            } else {
                Log.d(TAG + functionName,"Data transmission complete.")
                serverOffset = 0
            }
        } else {
            // 요청된 offset이 데이터 범위를 벗어나면 오류 응답
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, serverOffset, null)
            serverOffset = 0
        }

    }

    @SuppressLint("MissingPermission")
    fun senarioTest2_notification(
        device: BluetoothDevice?,
        requestId: Int,
        characteristic: BluetoothGattCharacteristic?

    ) {
        val functionName = "senarioTest2_notification"
        val data = "123123123123123123"
        Log.d(TAG + functionName, "senarioTest2_notification")
        Log.d(TAG + functionName, "uuid: ${characteristic!!.uuid.toString()}")
        Log.d(TAG + functionName, "device: ${device}")
        Log.d(TAG + functionName, "requestId: ${requestId.toString()}")
        characteristic.setValue(data)
        server.notifyCharacteristicChanged(device, characteristic, false)

    }

    fun senarioTest_onRead_request(device: BluetoothDevice?,
                                   requestId: Int,
                                   characteristic: BluetoothGattCharacteristic?) {
        when (scenario) {
            SCENARIO.SCENARIO_1 -> {
                senarioTest1_read_request(device, requestId, characteristic)
            }
            SCENARIO.SCENARIO_2 -> {

            }
            SCENARIO.SCENARIO_3 -> {

            }
            SCENARIO.SCENARIO_4 -> {
                senarioTest1_read_request(device, requestId, characteristic)

            }
            SCENARIO.SCENARIO_5 -> {

            }
            SCENARIO.SCENARIO_6 -> {
                senarioTest1_read_request(device, requestId, characteristic)

            }
            SCENARIO.SCENARIO_7 -> {

            }
            SCENARIO.SCENARIO_8 -> {

            }

        }

    }

    fun senarioTest_onWrite_request(device: BluetoothDevice,
                            requestId: Int,
                            characteristic: BluetoothGattCharacteristic,
                            value: ByteArray) {
        when (scenario) {
            SCENARIO.SCENARIO_1 -> {
                senarioTest1_write_request(device, requestId, characteristic, value)
            }
            SCENARIO.SCENARIO_2 -> {
                senarioTest1_write_request(device, requestId, characteristic, value)

            }
            SCENARIO.SCENARIO_3 -> {
                senarioTest1_write_request(device, requestId, characteristic, value)

            }
            SCENARIO.SCENARIO_4 -> {
                senarioTest1_write_request(device, requestId, characteristic, value)

            }
            SCENARIO.SCENARIO_5 -> {
                senarioTest1_write_request(device, requestId, characteristic, value)

            }
            SCENARIO.SCENARIO_6 -> {

            }
            SCENARIO.SCENARIO_7 -> {

            }
            SCENARIO.SCENARIO_8 -> {

            }


        }
    }

}