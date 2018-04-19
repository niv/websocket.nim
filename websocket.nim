import asyncdispatch, websocket/[shared, client, server]

export shared, client, server

proc read*(ws: AsyncWebSocket, cb: proc (opcode: Opcode, data: string): Future[void]) {.async.} =
  while true:
    let read = await ws.readData()
    await cb(read.opcode, read.data)

proc read*(ws: AsyncWebSocket, cb: proc (opcode: Opcode, data: string): Future[bool]) {.async.} =
  while true:
    let read = await ws.readData()
    if await(cb(read.opcode, read.data)):
      break