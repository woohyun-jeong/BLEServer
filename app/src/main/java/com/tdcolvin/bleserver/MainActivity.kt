package com.tdcolvin.bleserver

import android.Manifest
import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.ClickableText
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import com.tdcolvin.bleserver.ui.theme.BLEServerTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val allPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_ADVERTISE
        )
    }
    else {
        arrayOf(
            Manifest.permission.BLUETOOTH_ADMIN,
            Manifest.permission.BLUETOOTH
        )
    }

    private fun haveAllPermissions(context: Context): Boolean {
        return allPermissions
            .all { context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            BLEServerTheme {
                // A surface container using the 'background' color from the theme
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    ServerScreen()
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    @Composable
    fun ServerScreen(viewModel: ServerViewModel = viewModel()) {
        val context = LocalContext.current
        var allPermissionsGranted by remember {
            mutableStateOf (haveAllPermissions(context))
        }

        val uiState by viewModel.uiState.collectAsStateWithLifecycle()

        Column {
            if (allPermissionsGranted) {
                ServerStatus(
                    serverRunning = uiState.serverRunning,
                    onStartServer = { viewModel.startServer() },
                    onStopServer = { viewModel.stopServer() }
                )
                // 각 체크박스 상태 관리
                var checked1 by remember { mutableStateOf(true) }
                var checked2 by remember { mutableStateOf(false) }
                var checked3 by remember { mutableStateOf(false) }
                var checked4 by remember { mutableStateOf(false) }
                var checked5 by remember { mutableStateOf(false) }
                var checked6 by remember { mutableStateOf(false) }

                // 체크박스 선택 시, 다른 체크박스들을 해제하는 함수
                fun onCheckedChange(selected: SCENARIO, checked: Boolean) {
                    // 체크된 체크박스를 제외한 모든 체크박스를 해제
                    checked1 = (selected == SCENARIO.SCENARIO_1) && checked
                    checked2 = (selected == SCENARIO.SCENARIO_2) && checked
                    checked3 = (selected == SCENARIO.SCENARIO_3) && checked
                    checked4 = (selected == SCENARIO.SCENARIO_4) && checked
                    checked5 = (selected == SCENARIO.SCENARIO_5) && checked
                    checked6 = (selected == SCENARIO.SCENARIO_6) && checked
                    viewModel.scenario = selected
                }


                CheckBoxRow("시나리오 1", value = checked1, onClick = { onCheckedChange(SCENARIO.SCENARIO_1, !checked1) })
                CheckBoxRow("시나리오 2", value = checked2, onClick = { onCheckedChange(SCENARIO.SCENARIO_2, !checked2) })
                CheckBoxRow("시나리오 3", value = checked3, onClick = { onCheckedChange(SCENARIO.SCENARIO_3, !checked3) })
                CheckBoxRow("시나리오 4", value = checked4, onClick = { onCheckedChange(SCENARIO.SCENARIO_4, !checked4) })
                CheckBoxRow("시나리오 5", value = checked5, onClick = { onCheckedChange(SCENARIO.SCENARIO_5, !checked5) })
                CheckBoxRow("시나리오 6", value = checked6, onClick = { onCheckedChange(SCENARIO.SCENARIO_6, !checked6) })

            }
            else {
                val launcher = rememberLauncherForActivityResult(contract = ActivityResultContracts.RequestMultiplePermissions()) { granted ->
                    allPermissionsGranted = granted.values.all { it }
                }
                Button(onClick = { launcher.launch(allPermissions)}) {
                    Text("Grant Permission")
                }
            }
        }
    }

    @Composable
    fun CheckBoxRow(text: String, value: Boolean, onClick: (Any) -> Unit) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = value, onCheckedChange = onClick)
            ClickableText(
                text = AnnotatedString(text), onClick = onClick, modifier = Modifier.fillMaxWidth()
            )
        }
    }

    @Composable
    fun ServerStatus(serverRunning: Boolean, onStartServer: () -> Unit, onStopServer: () -> Unit) {
        if (serverRunning) {
            Text("Server running")
            Button(onClick = onStopServer) {
                Text("Stop server")
            }
        }
        else {
            Text("Server not running")
            Button(onClick = onStartServer) {
                Text("Start server")
            }
        }
    }

    @Composable
    fun NamesReceived(names: List<String>) {
        LazyColumn {
            items(names) { name ->
                Text(name)
            }
        }
    }
}

class ServerViewModel(application: Application): AndroidViewModel(application) {
    private val _uiState = MutableStateFlow(ServerUIState())
    val uiState = _uiState.asStateFlow()
    private var server: BluetoothCTFServer? = null
    val context = application
    var scenario:SCENARIO = SCENARIO.SCENARIO_1

    init {
        viewModelScope.launch {
            server?.namesReceived?.collect { names ->
                _uiState.update { it.copy(namesReceived = names) }
            }
        }
    }

    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_ADVERTISE, PERMISSION_BLUETOOTH_CONNECT])
    fun startServer() {
        viewModelScope.launch {
            server = BluetoothCTFServer(context)
            server?.scenario = scenario
            server?.startServer()
            _uiState.update { it.copy(serverRunning = true) }
        }
    }
    @RequiresPermission(allOf = [PERMISSION_BLUETOOTH_ADVERTISE, PERMISSION_BLUETOOTH_CONNECT])
    fun stopServer() {
        viewModelScope.launch {
            server?.stopServer()
            _uiState.update { it.copy(serverRunning = false) }
        }
    }

}

data class ServerUIState(
    val serverRunning: Boolean = false,
    val namesReceived: List<String> = emptyList()
)