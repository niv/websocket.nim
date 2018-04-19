import ../websocket, asyncnet, asyncdispatch

let ws = waitFor newAsyncWebsocketClient("echo.websocket.org",
  Port 80, "/?encoding=text", ssl = false)
echo "connected!"

proc reader(opcode: Opcode, data: string) {.async.} =
  echo "(opcode: ", opcode, ", data: ", data, ")"

proc ping() {.async.} =
  while true:
    await sleepAsync(6000)
    echo "ping"
    await ws.sendPing()

asyncCheck ws.read(reader)
asyncCheck ping()
runForever()