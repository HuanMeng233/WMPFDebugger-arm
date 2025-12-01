const getMainModule = () => {
    return Process.findModuleByName("WeChatAppEx");
}
console.log("[hook] main module:", getMainModule());