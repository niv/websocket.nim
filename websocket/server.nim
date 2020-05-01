## Example
## -------
##
## .. code-block::nim
##   import websocket, asynchttpserver, asyncnet, asyncdispatch
##
##   let server = newAsyncHttpServer()
##
##   proc cb(req: Request) {.async.} =
##     let (ws, error) = await verifyWebsocketRequest(req, "myfancyprotocol")
##
##     if ws.isNil:
##       echo "WS negotiation failed: ", error
##       await req.respond(Http400, "Websocket negotiation failed: " & $error)
##       req.client.close()
##       return
##
##     echo "New websocket customer arrived!"
##     while true:
##       let (opcode, data) = await ws.readData()
##       try:
##         echo "(opcode: ", opcode, ", data length: ", data.len, ")"
##
##         case opcode
##         of Opcode.Text:
##           await ws.sendText("thanks for the data!")
##         of Opcode.Binary:
##           await ws.sendBinary(data)
##         of Opcode.Close:
##           asyncCheck ws.close()
##           let (closeCode, reason) = extractCloseData(data)
##           echo "socket went away, close code: ", closeCode, ", reason: ", reason
##         else: discard
##       except:
##         echo "encountered exception: ", getCurrentExceptionMsg()
##
##   waitFor server.serve(Port(8080), cb)

import asyncnet, asyncdispatch, asynchttpserver, base64,
  strutils, nativesockets

when (NimMajor, NimMinor) < (0, 18):
  import securehash
else:
  import std/sha1

import private/hex

import shared

type HeaderVerificationError* {.pure.} = enum
  none
    ## No error.
  unsupportedVersion
    ## The Sec-Websocket-Version header gave an unsupported version.
    ## The only currently supported version is 13.
  noKey
    ## No Sec-Websocket-Key was provided.
  protocolAdvertised
    ## A protocol was advertised but the server gave no protocol.
  noProtocolsSupported
    ## None of the advertised protocols match the server protocol.
  noProtocolAdvertised
    ## Server asked for a protocol but no protocol was advertised.

proc `$`*(error: HeaderVerificationError): string =
  const errorTable: array[HeaderVerificationError, string] = [
    "no error",
    "the only supported sec-websocket-version is 13",
    "no sec-websocket-key provided",
    "server does not support protocol negotation",
    "no advertised protocol supported",
    "no protocol advertised"
  ]
  result = errorTable[error]

proc makeHandshakeResponse*(key, protocol: string): string =
  let sh = secureHash(key & "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
  let acceptKey = decodeHex($sh).encode

  result = "HTTP/1.1 101 Web Socket Protocol Handshake\c\L"
  result.add("Sec-Websocket-Accept: " & acceptKey & "\c\L")
  result.add("Connection: Upgrade\c\LUpgrade: websocket\c\L")
  if protocol.len != 0:
    result.add("Sec-Websocket-Protocol: " & protocol & "\c\L")
  result.add "\c\L"

proc verifyHeaders(
  headers: HttpHeaders, protocol: string
): tuple[handshake: string, error: HeaderVerificationError] =
  # if headers.hasKey("sec-websocket-extensions"):
    # TODO: transparently support extensions

  if headers.getOrDefault("sec-websocket-version") != "13":
    return ("", unsupportedVersion)

  if not headers.hasKey("sec-websocket-key"):
    return ("", noKey)

  if headers.hasKey("sec-websocket-protocol"):
    if protocol.len == 0:
      return ("", protocolAdvertised)

    block protocolCheck:
      let prot = protocol.toLowerAscii()

      for it in headers["sec-websocket-protocol"].split(','):
        if prot == it.strip.toLowerAscii():
          break protocolCheck

      return ("",  noProtocolsSupported)
  elif protocol.len != 0:
    return ("", noProtocolAdvertised)

  return (makeHandshakeResponse(headers["sec-websocket-key"], protocol), none)

proc verifyWebsocketRequest*(
  client: AsyncSocket, headers: HttpHeaders, protocol = ""
): Future[tuple[ws: AsyncWebSocket, error: HeaderVerificationError]] {.async.} =
  ## Verifies the request is a websocket request:
  ## * Supports protocol version 13 only
  ## * Does not support extensions (yet)
  ## * Will auto-negotiate a compatible protocol based on your `protocol` param
  ##
  ## If all validations pass, will give you a tuple (AsyncWebSocket, "").
  ## You can pass in a empty protocol param to not perform negotiation; this is
  ## the equivalent of accepting all protocols the client might request.
  ##
  ## If the client does not send any protocols, but you have given one, the
  ## request will fail.
  ##
  ## If validation FAILS, the response will be (nil, human-readable failure reason).
  ##
  ## After successful negotiation, you can immediately start sending/reading
  ## websocket frames.
  let (handshake, error) = verifyHeaders(headers, protocol)
  if error != HeaderVerificationError.none:
    return (nil, error)

  await client.send(handshake)

  return (
    AsyncWebSocket(
      kind: SocketKind.Server,
      sock: client,
      protocol: protocol
    ),
    none
  )

proc verifyWebsocketRequest*(
  req: asynchttpserver.Request, protocol = ""
): Future[tuple[ws: AsyncWebSocket, error: HeaderVerificationError]] =
  ## Convenience wrapper for AsyncHttpServer requests.
  return verifyWebsocketRequest(req.client, req.headers, protocol)
