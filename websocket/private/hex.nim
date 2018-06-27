proc nibbleFromChar(c: char): int =
  case c
  of '0'..'9': result = ord(c) - ord('0')
  of 'a'..'f': result = ord(c) - ord('a') + 10
  of 'A'..'F': result = ord(c) - ord('A') + 10
  else: discard 255

proc decodeHex*(str: string): string =
  let length = len(str) div 2
  result = newString(length)
  for i in 0..<length:
    result[i] = chr((nibbleFromChar(str[2 * i]) shl 4) or nibbleFromChar(str[2 * i + 1]))

proc nibbleToChar(nibble: int): char {.inline.} =
  const byteMap = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
  return byteMap[nibble]

proc encodeHex*(str: string): string =
  let length = len(str)
  result = newString(length * 2)
  for i in 0..<length:
    let a = ord(str[i]) shr 4 and 0x0f
    let b = ord(str[i]) and 0x0f
    result[i * 2] = nibbleToChar(a)
    result[i * 2 + 1] = nibbleToChar(b)
