import frida from 'frida';

const frida_server = async () => {
    const localDevice = await frida.getLocalDevice();
    const processes = await localDevice.enumerateProcesses({ scope: frida.Scope.Metadata });

    // 专门查找 WeChatAppEx Helper 进程
    const wmpfProcess = processes.find(process => process.name === "WeChatAppEx Helper");

    if (!wmpfProcess) {
        throw new Error("[frida] WeChatAppEx Helper process not found");
        // return; // 这行在 throw 之后其实不会执行，可以省略
    }

    const wmpfPid = wmpfProcess.pid;

    console.log(`[frida] Found WeChatAppEx Helper process with PID: ${wmpfPid}`);
};

// 2. 后调用函数
frida_server();