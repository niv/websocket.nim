import ../websocket, asyncnet, asyncdispatch

let ws = waitFor newAsyncWebsocketClient("echo.websocket.org",
  Port 80, "/?encoding=text", ssl = false)
echo "connected!"

proc ping() {.async.} =
  while true:
    await sleepAsync(6000)
    echo "ping"
    await ws.sendPing()

proc read() {.async.} =
  while true:
    let data = await ws.readData()
    echo "(opcode: ", data.opcode, ", data: ", data.data, ")"

asyncCheck read()
asyncCheck ping()
runForever()