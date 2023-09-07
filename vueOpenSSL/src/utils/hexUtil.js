export function hexToUint8Array(hexString) {
  const length = hexString.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const byteValue = parseInt(hexString.substr(i * 2, 2), 16);
    uint8Array[i] = byteValue;
  }

  return uint8Array;
}

export function uint8ArrayToHex(uint8Array) {
  const hexString = Array.from(uint8Array, byte => {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('');

  return hexString;
}

export function stringToHex(str) {
  let val = "";
  for (let i = 0; i < str.length; i++) {
    if (val == "")
      val = str.charCodeAt(i).toString(16);
    else
      val += str.charCodeAt(i).toString(16);
  }
  return val;
}

export function stringToUint8Array(str) {
  const length = str.length;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    const charCode = str.charCodeAt(i);
    uint8Array[i] = charCode;
  }

  return uint8Array;
}