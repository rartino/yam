// --- Tiny QR renderer (no deps). Public API: window.drawQRCode(canvas, text, opts) ---
(() => {
  // ---- Tables (cut to versions 1..10, ECC M only) ----
  const EC_M = {
    1:[10,1,16,0,0], 2:[16,1,28,0,0], 3:[26,1,44,0,0], 4:[18,2,32,0,0], 5:[24,2,43,0,0],
    6:[16,4,27,0,0], 7:[18,4,31,0,0], 8:[22,2,38,2,39], 9:[22,3,36,2,37], 10:[26,4,43,1,44],        
  };
  const REM_BITS = {1:0,2:7,3:7,4:7,5:7,6:7,7:0,8:0,9:0,10:0};
  const ALIGN = {
    1:[],2:[6,18],3:[6,22],4:[6,26],5:[6,30],6:[6,34],7:[6,22,38],8:[6,24,42],9:[6,26,46],10:[6,28,50]
  };
  const FMT_M = [
    0b101010000010010, 0b101000100100101, 0b101111001111100, 0b101101101001011,
    0b100010111111001, 0b100000011001110, 0b100111110010111, 0b100101010100000
  ];
  const VER_INFO = {
    7:  0b000111110010010100, 8:  0b001000010110111100,
    9:  0b001001101010011001, 10: 0b001010010011010011
  };

  // ---- GF(256) for Reed–Solomon ----
  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  (function initGF(){
    let x = 1;
    for (let i=0;i<255;i++){ GF_EXP[i]=x; GF_LOG[x]=i; x<<=1; if (x&0x100) x^=0x11D; }
    for (let i=255;i<512;i++) GF_EXP[i]=GF_EXP[i-255];
  })();
  function gfMul(a,b){ if (a===0||b===0) return 0; return GF_EXP[GF_LOG[a]+GF_LOG[b]]; }
  function rsGenPoly(deg){
    let poly = new Uint8Array(deg+1); poly[0]=1;
    for (let d=0; d<deg; d++){
      const nxt = new Uint8Array(deg+1);
      for (let i=0;i<=d;i++){
        nxt[i+1] ^= poly[i];
        nxt[i]   ^= gfMul(poly[i], GF_EXP[d]);
      }
      poly = nxt;
    }
    return poly;
  }
  function rsComputeECC(data, ecw){
    const gen = rsGenPoly(ecw);
    const res = new Uint8Array(ecw);
    for (let i=0;i<data.length;i++){
      const factor = data[i] ^ res[0];
      res.copyWithin(0,1); res[res.length-1]=0;
      if (factor!==0){
        for (let j=0;j<ecw;j++){
          res[j] ^= gfMul(gen[j+1], factor);
        }
      }
    }
    return res;
  }

  // ---- Bit buffer helper ----
  class BitBuf {
    constructor(){ this.bits=[]; }
    put(val, n){
      for (let i=n-1;i>=0;i--) this.bits.push((val>>>i)&1);
    }
    putBytes(u8){
      for (const b of u8) this.put(b,8);
    }
    padToBytes(){
      while (this.bits.length % 8) this.bits.push(0);
    }
    get length(){ return this.bits.length; }
    toBytes(){
      const out = new Uint8Array(this.bits.length/8|0);
      for (let i=0;i<out.length;i++){
        let v=0; for (let j=0;j<8;j++){ v=(v<<1)|this.bits[i*8+j]; }
        out[i]=v;
      }
      return out;
    }
  }

  // ---- Capacity & structure helpers ----
  function dataCapacityBits(ver){
    const cfg = EC_M[ver];
    const k = cfg[1]*cfg[2] + cfg[3]*cfg[4];
    return k * 8;
  }
  function makeBlocks_M(ver, dataBytes){
    const [ecw, g1n, g1k, g2n, g2k] = EC_M[ver];
    let off = 0;
    const blocks = [];
    for (let i=0;i<g1n;i++){ blocks.push({data: dataBytes.slice(off, off+g1k), ec: null}); off+=g1k; }
    for (let i=0;i<g2n;i++){ blocks.push({data: dataBytes.slice(off, off+g2k), ec: null}); off+=g2k; }
    for (const b of blocks){ b.ec = rsComputeECC(b.data, ecw); }
    const maxK = Math.max(g1k, g2k);
    const out = [];
    for (let i=0;i<maxK;i++){
      for (const b of blocks){ if (i < b.data.length) out.push(b.data[i]); }
    }
    for (let i=0;i<ecw;i++){
      for (const b of blocks){ out.push(b.ec[i]); }
    }
    return new Uint8Array(out);
  }

  // ---- Matrix building ----
  function sizeFor(ver){ return 17 + 4*ver; }
  function emptyMatrix(n){ const m=new Array(n); for (let y=0;y<n;y++){ m[y]=new Array(n).fill(null); } return m; }

  function placeFinder(m, x, y){
    for (let dy=-1; dy<=7; dy++){
      for (let dx=-1; dx<=7; dx++){
        const xx = x+dx, yy=y+dy;
        if (xx<0||yy<0||yy>=m.length||xx>=m.length) continue;
        const on = (dx>=0&&dx<=6 && dy>=0&&dy<=6 &&
                   (dx===0||dx===6||dy===0||dy===6 || (dx>=2&&dx<=4 && dy>=2&&dy<=4)));
        m[yy][xx] = on ? 1 : 0;
      }
    }
  }
  function placeTiming(m){
    const n=m.length;
    for (let i=0;i<n;i++){
      if (m[6][i]===null) m[6][i] = (i%2===0)?1:0;
      if (m[i][6]===null) m[i][6] = (i%2===0)?1:0;
    }
  }
  function placeAlign(m, ver){
    const centers = ALIGN[ver]||[];
    if (centers.length===0) return;
    for (let cy of centers){
      for (let cx of centers){
        if ((cx===6 && cy===6)||(cx===m.length-7 && cy===6)||(cx===6 && cy===m.length-7)) continue;
        for (let dy=-2;dy<=2;dy++){
          for (let dx=-2;dx<=2;dx++){
            const xx=cx+dx, yy=cy+dy;
            m[yy][xx] = (Math.max(Math.abs(dx),Math.abs(dy))===2) ? 1 : (dx===0&&dy===0 ? 1 : 0);
          }
        }
      }
    }
  }
  function reserveFormatAreas(m){
    const n=m.length;
    for (let i=0;i<9;i++){
      if (i!==6){ m[8][i]=0; m[i][8]=0; }
    }
    for (let i=0;i<8;i++){ m[n-1-i][8]=0; m[8][n-1-i]=0; }
    m[n-8][8]=1;
  }
  function placeVersionInfo(m, ver){
    if (ver < 7) return;
    const n = m.length, bits = VER_INFO[ver];  // MSB-first constant
    for (let i=0;i<18;i++){
      const b = (bits >> (17 - i)) & 1;        // write MSB→LSB
      const r = Math.floor(i/3), c = i%3;
      m[r][n-11+c] = b;
      m[n-11+c][r] = b;
    }
  }
  function placeDarkModule(m, ver) {
    if (ver >= 2) { // Dark module exists for all versions except 1
      const n = m.length;
      m[4 * ver + 9][8] = 1; // Standard position for dark module
    }
  }
  function fillData(m, dataBits, maskId) {
    const n = m.length;
    let i = 0;
    let dirUp = true;
    
    for (let x = n-1; x>=0; x-=2){
      if (x===6) x--;
      for (let yInner=0; yInner<n; yInner++){
        const y = dirUp ? (n-1-yInner) : yInner;
        for (let dx=0; dx<2; dx++){
          const xx = x-dx, yy=y;
          if (m[yy][xx] !== null) continue;
          
          let bit = (i<dataBits.length) ? dataBits[i++] : 0;
          // Apply mask ONLY to data cells (not reserved areas)
          if (mask(maskId, xx, yy)) bit ^= 1;
          m[yy][xx] = bit;
        }
      }
      dirUp = !dirUp;
    }
  }

  function mask(id, x, y){
    switch(id){
      case 0: return ((x+y) % 2) === 0;
      case 1: return (y % 2) === 0;
      case 2: return (x % 3) === 0;
      case 3: return ((x + y) % 3) === 0;
      case 4: return (((Math.floor(y/2) + Math.floor(x/3)) % 2) === 0);
      case 5: return (((x*y) % 2) + ((x*y) % 3)) === 0;
      case 6: return ((((x*y) % 2) + ((x*y) % 3)) % 2) === 0;
      case 7: return ((((x+y) % 2) + ((x*y) % 3)) % 2) === 0;
      default: return false;
    }
  }

  // ---- Penalty scoring ----
  function penalty(m){
    const n = m.length;
    let p = 0;
    
    // Rule 1: 5+ same modules in row/column
    for (let y = 0; y < n; y++) {
      let run = 1;
      for (let x = 1; x < n; x++) {
        if (m[y][x] === m[y][x-1]) {
          run++;
        } else {
          if (run >= 5) p += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
  
    for (let x = 0; x < n; x++) {
      let run = 1;
      for (let y = 1; y < n; y++) {
        if (m[y][x] === m[y-1][x]) {
          run++;
        } else {
          if (run >= 5) p += 3 + (run - 5);
          run = 1;
        }
      }
      if (run >= 5) p += 3 + (run - 5);
    }
  
    // Rule 2: 2x2 blocks of same color
    for (let y = 0; y < n-1; y++) {
      for (let x = 0; x < n-1; x++) {
        if (m[y][x] === m[y][x+1] && 
            m[y][x] === m[y+1][x] && 
            m[y][x] === m[y+1][x+1]) {
          p += 3;
        }
      }
    }
  
    // Rule 3: finder-like patterns (10111010000 and 00001011101)
    const pat1 = [1,0,1,1,1,0,1,0,0,0,0]; // 10111010000
    const pat2 = [0,0,0,0,1,0,1,1,1,0,1]; // 00001011101
    
    function checkPattern(arr, start, line) {
      for (let k = 0; k < 11; k++) {
        if (line[start + k] !== arr[k]) return false;
      }
      return true;
    }
  
    // Check rows
    for (let y = 0; y < n; y++) {
      const row = m[y];
      for (let x = 0; x <= n-11; x++) {
        if (checkPattern(pat1, x, row) || checkPattern(pat2, x, row)) {
          p += 40;
        }
      }
    }
  
    // Check columns
    for (let x = 0; x < n; x++) {
      const col = new Array(n);
      for (let y = 0; y < n; y++) col[y] = m[y][x];
      for (let y = 0; y <= n-11; y++) {
        if (checkPattern(pat1, y, col) || checkPattern(pat2, y, col)) {
          p += 40;
        }
      }
    }
  
    // Rule 4: dark module ratio
    let darkCount = 0;
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        if (m[y][x] === 1) darkCount++;
      }
    }
    
    const ratio = (darkCount * 100) / (n * n);
    const deviation = Math.abs(ratio - 50);
    p += Math.floor(deviation / 5) * 10;
  
    return p;
  }
  function writeFormat(m, fmt15) {
    const n = m.length;
    
    // Top-left format area (around finder pattern)
    for (let i = 0; i < 8; i++) {
      m[8][i < 6 ? i : i + 1] = (fmt15 >> (14 - i)) & 1;
    }
    m[8][7] = (fmt15 >> 7) & 1;
    m[8][8] = (fmt15 >> 8) & 1;
    m[7][8] = (fmt15 >> 9) & 1;
    
    for (let i = 10; i < 15; i++) {
      m[14 - i][8] = (fmt15 >> (14 - i)) & 1;
    }
    
    // Top-right format area
    for (let i = 0; i < 7; i++) {
      m[i][8] = (fmt15 >> i) & 1;
    }
    
    // Bottom-left format area
    for (let i = 0; i < 7; i++) {
      m[8][n - 1 - i] = (fmt15 >> i) & 1;
    }
  }

  // ---- Encode ----
  function encodeBytes(bytes){
    for (let ver=1; ver<=10; ver++){
      const cap = dataCapacityBits(ver);
      const cciBits = (ver<=9) ? 8 : 16;
      const needed = 4 + cciBits + bytes.length*8 + 4;
      if (needed <= cap) {
        const bb = new BitBuf();
        bb.put(0b0100,4);
        bb.put(bytes.length, cciBits);
        bb.putBytes(bytes);
        const toTerm = Math.min(4, cap - bb.length);
        bb.put(0, toTerm);
        bb.padToBytes();
        const needBytes = (cap/8|0) - (bb.length/8|0);
        const pads = new Uint8Array(needBytes);
        for (let i=0;i<needBytes;i++) pads[i] = (i%2) ? 0x11 : 0xEC;
        const dataBytes = new Uint8Array(bb.toBytes().length + pads.length);
        dataBytes.set(bb.toBytes(), 0); dataBytes.set(pads, bb.toBytes().length);
        return { ver, dataBytes };
      }
    }
    throw new Error('QR: text too long for version ≤ 10 @ ECC M');
  }

  // ---- Public: draw to canvas ----
  function drawQRCode(canvas, text, {margin=2, scale=4} = {}){
    const bytes = (new TextEncoder()).encode(text);
    const { ver, dataBytes } = encodeBytes(bytes);
    const finalCW = makeBlocks_M(ver, dataBytes);

    const n = sizeFor(ver);
    let bestMask = 0, bestMatrix = null, bestScore = Infinity;

    // FIXED: Correct MSB-first bit order
    const dataBits = new Array(finalCW.length*8 + REM_BITS[ver]);
    for (let i=0;i<finalCW.length;i++){
      const b = finalCW[i];
      for (let k=0;k<8;k++) dataBits[i*8 + k] = (b>>(7-k))&1; // FIXED
    }
    // Add remainder bits (always 0)
    for (let i=finalCW.length*8; i<dataBits.length; i++){
      dataBits[i] = 0;
    }

    for (let maskId=0; maskId<8; maskId++){
const m = emptyMatrix(n);
      placeFinder(m,0,0); placeFinder(m,n-7,0); placeFinder(m,0,n-7);
      placeTiming(m); placeAlign(m, ver); reserveFormatAreas(m); 
      placeVersionInfo(m, ver);
      placeDarkModule(m, ver);
      fillData(m, dataBits, maskId);
      writeFormat(m, FMT_M[maskId]);
      const score = penalty(m);
      if (score < bestScore){ bestScore=score; bestMask=maskId; bestMatrix=m; }
    }

    const m = bestMatrix;
    const px = Math.max(1, scale|0);
    const quiet = Math.max(0, margin|0);
    const dim = (n + quiet*2) * px;
    canvas.width = dim; canvas.height = dim;
    const ctx = canvas.getContext('2d', { willReadFrequently:false });
    ctx.fillStyle = '#fff'; ctx.fillRect(0,0,dim,dim);
    ctx.fillStyle = '#000';
    for (let y=0;y<n;y++){
      for (let x=0;x<n;x++){
        if (m[y][x]) ctx.fillRect((x+quiet)*px, (y+quiet)*px, px, px);
      }
    }
  }

  window.drawQRCode = drawQRCode;
})();
