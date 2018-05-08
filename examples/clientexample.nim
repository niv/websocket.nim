import ../websocket, asyncnet, asyncdispatch

let ws = waitFor newAsyncWebsocketClient("localhost", Port(8080), path = "/")
echo "connected!"

proc ping() {.async.} =
  while true:
    await sleepAsync(6000)
    echo "ping"
    await ws.sendPing()

proc read() {.async.} =
  while true:
    let (opcode, data) = await ws.readData()
    echo "(opcode: ", opcode, ", data: ", data, ")"

asyncCheck read()
asyncCheck ping()
runForever()