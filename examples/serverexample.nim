import ../websocket, asynchttpserver, asyncnet, asyncdispatch

let server = newAsyncHttpServer()

proc cb(req: Request) {.async.} =
  let (ws, error) = await verifyWebsocketRequest(req, "myfancyprotocol")

  if ws.isNil:
    echo "WS negotiation failed: ", error
    await req.respond(Http400, "Websocket negotiation failed: " & error)
    req.client.close()
    return

  echo "New websocket customer arrived!"
  while true:
    let (opcode, data) = await ws.readData()
    try:
      echo "(opcode: ", opcode, ", data length: ", data.len, ")"

      case opcode
      of Opcode.Text:
        waitFor ws.sendText("thanks for the data!")
      of Opcode.Binary:
        waitFor ws.sendBinary(data)
      of Opcode.Close:
        asyncCheck ws.close()
        let (closeCode, reason) = extractCloseData(data)
        echo "socket went away, close code: ", closeCode, ", reason: ", reason
      else: discard
    except:
      echo "encountered exception: ", getCurrentExceptionMsg()

waitFor server.serve(Port(8080), cb)