"""Ghost Touch offline firmware reconstruction and solver (numpy/scipy).
Only --submit contacts the official challenge endpoint.
"""
from pathlib import Path
import argparse, datetime, hashlib, json, struct, urllib.request, zlib
import numpy as np

ROOT = Path(__file__).resolve().parent

def decode_model():
    elf = (ROOT/'for_user/firmware_m7.elf').read_bytes()
    enc = elf[0x2630:0x2630+0x5b14]
    state = 0x43545731
    decoded = bytearray()
    for i in range(len(enc)):
        state ^= (state << 13) & 0xffffffff
        state ^= state >> 17
        state ^= (state << 5) & 0xffffffff
        decoded.append(enc[(0x6c5+0x1003*i)%len(enc)] ^ ((state>>9)^(state>>24))&255)
    assert zlib.crc32(decoded[:-4]) == struct.unpack_from('<I',decoded,len(decoded)-4)[0]
    model = bytearray(decoded[:-4])
    model[:0x2000] = np.frombuffer(model[:0x2000],np.uint8).reshape(256,32).T.copy().tobytes()
    (ROOT/'model_decoded.bin').write_bytes(model)
    return model

class Model:
    def __init__(self):
        self.raw = decode_model()
    def arr(self,off,count,dtype=np.int8):
        return np.frombuffer(self.raw,dtype,count,off).astype(np.int64)
    def encode(self,q):
        i=np.arange(128)[:,None]
        base=39*i*i-99*i+np.array([109,192])
        return ((base+np.array([1,-1])*(-1)**i*q)%256).reshape(256)
    def quality(self,points):
        p=np.asarray(points,dtype=np.int64)
        assert p.shape==(128,2)
        stats={'samples':128,'min':p.min(axis=0).tolist(),'max':p.max(axis=0).tolist(),
               'span':np.ptp(p,axis=0).tolist(),'manhattan_length':int(np.abs(np.diff(p,axis=0)).sum()),
               'max_step':int(np.abs(np.diff(p,axis=0)).max()),
               'max_second_difference':int(np.abs(np.diff(p,n=2,axis=0)).max()),
               'max_third_difference':int(np.abs(np.diff(p,n=3,axis=0)).max())}
        assert np.all((p>=3712)&(p<=3967)), 'Outside the browser acquisition window'
        assert min(stats['span'])>=224
        assert 2500<=stats['manhattan_length']<=14000
        assert stats['max_step']<=128
        assert stats['max_second_difference']<=56
        assert stats['max_third_difference']<=80
        return stats
    def rnn(self,z,reverse=False):
        z=z.reshape(128,2)
        shift=0xa20*reverse
        lut=self.arr(0x20cc+512*reverse,512,'u1').reshape(2,256)
        mask=self.arr(0x24cc+256*reverse,256,'u1').reshape(128,2)
        win=self.arr(0x26cc+shift,96).reshape(48,2)
        rec=self.arr(0x272c+shift,2304).reshape(48,48)
        bias=self.arr(0x302c+shift,48,'<i4')
        h=np.zeros(48,dtype=np.int64)
        out=np.zeros((8,48),dtype=np.int64)
        for t in range(128):
            j=127-t if reverse else t
            if t%16==0: key=((0xa7 if reverse else 0x5d)^(53*(j//16)))&255
            zx,zy=z[j]
            a=int(lut[0,zx^key^mask[j,0]])
            b=int(lut[1,zy^(((key<<3)|(key>>5))&255)^mask[j,1]])
            inp=np.array([a-256 if a>=128 else a,b-256 if b>=128 else b])
            h=np.clip(h+np.rint((bias+win@inp+rec@h)/128).astype(np.int64),0,127)
            if (t+1)%16==0: out[j//16]=h
            key=(key+17*t+29+(zx>>4)+3*(zy>>4))&255
            key=(((key<<1)|(key>>7))^(a>>4)^(b>>3))&255
        return out
    def evaluate(self,q,verbose=True):
        z=self.encode(np.asarray(q,dtype=np.int64))
        s=(z+128)%256-128
        hidden=np.clip(np.rint((self.arr(0x2000,32,'<i4')+self.arr(0,8192).reshape(32,256)@s)/128),0,127).astype(np.int64)
        dense=self.arr(0x20c0,2,'<i4')+self.arr(0x2080,64).reshape(2,32)@hidden
        densemargin=dense[1]-dense[0]-self.arr(0x20c8,1,'<i4')[0]
        fw,bw=self.rnn(z),self.rnn(z,True)
        segments=[]
        for j in range(8):
            zz=s[j*32:(j+1)*32].reshape(16,2)
            features=np.r_[fw[j],bw[j],zz[0],zz[-1],np.rint(zz.mean(axis=0)).astype(np.int64)]
            logits=self.arr(0x449c+j*12,3,'<i4')+self.arr(0x3b0c+j*306,306).reshape(3,102)@features
            segments.append(logits[0]-logits[1:]-self.arr(0x44fc+j*8,2,'<i4'))
        features=np.c_[fw,bw].reshape(768)
        logits=self.arr(0x4e3c,3,'<i4')+self.arr(0x453c,2304).reshape(3,768)@features
        globalmargin=logits[0]-logits[1:]-self.arr(0x4e48,2,'<i4')
        residue=(self.arr(0x4e50,3072).reshape(12,256)@z)%257
        d=abs(residue-self.arr(0x5a80,12,'<i4'))
        hashmargin=self.arr(0x5ae0,12,'<i4')-np.minimum(d,257-d)
        if verbose:
            print('dense',densemargin,'segments',np.array(segments).flatten(),'global',globalmargin,'hash',hashmargin,flush=True)
        return densemargin,np.array(segments).flatten(),globalmargin,hashmargin
    def summary(self):
        for off,n,dtype in [(0x2000,32,'<i4'),(0x2080,32,'i1'),(0x20a0,32,'i1'),(0x20c0,3,'<i4'),
            (0x24cc,32,'u1'),(0x25cc,32,'u1'),(0x302c,48,'<i4'),(0x26cc,96,'i1'),
            (0x449c,24,'<i4'),(0x44fc,16,'<i4'),(0x4e3c,5,'<i4'),(0x5a50,48,'<i4')]:
            print(hex(off),self.arr(off,n,dtype))

    def constant_probe(self):
        # Check whether masks turn a fixed RNN symbol into a coherent gesture.
        bx = np.repeat(np.arange(256),256)
        by = np.tile(np.arange(256),256)
        invx = np.argsort(self.arr(0x20cc,256,'u1'))
        invy = np.argsort(self.arr(0x21cc,256,'u1'))
        mask = self.arr(0x24cc,256,'u1').reshape(128,2)
        key = np.zeros(65536,dtype=np.int64)
        score=np.zeros(65536)
        prev=None
        for i in range(128):
            if i%16==0: key[:]=0x5d ^ ((53*(i//16))&255)
            zx=invx[bx]^key^mask[i,0]
            zy=invy[by]^(((key<<3)|(key>>5))&255)^mask[i,1]
            base=39*i*i-99*i
            qx=(((zx-109-base)*((-1)**i)+128)%256)-128
            qy=(((zy-192-base)*((-1)**(i+1))+128)%256)-128
            if prev is not None:
                score+=(qx-prev[0])**2+(qy-prev[1])**2
            prev=(qx,qy)
            v=(key+17*i+29+(zx>>4)+3*(zy>>4))&255
            key=(((v<<1)|(v>>7))^(bx>>4)^(by>>3))&255
        ids=np.argsort(score)[:10]
        print('constant probes:',[(int(bx[j]),int(by[j]),int(score[j])) for j in ids])

if __name__=='__main__':
    ap=argparse.ArgumentParser()
    ap.add_argument('--submit',action='store_true',help='Send final points only to the official challenge UI capture API')
    args=ap.parse_args()
    m=Model()
    if (ROOT/'candidate.json').exists():
        points=json.loads((ROOT/'candidate.json').read_text())
        print('quality',m.quality(points),flush=True)
        result=m.evaluate(np.array(points)-3840)
        if args.submit:
            assert all(np.all(np.array(x)>=0) for x in result), 'Offline verification failed'
            url='http://3.36.129.171:8080/api/capture'
            body=json.dumps({'points':points},separators=(',',':')).encode()
            req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST')
            with urllib.request.urlopen(req,timeout=30) as response:
                raw=response.read()
                status=response.status
            response=json.loads(raw)
            proof={'url':url,'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'http_status':status,'request_sha256':hashlib.sha256(body).hexdigest(),
                   'response':response,'raw_response':raw.decode()}
            (ROOT/'verification.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2))
            print(raw.decode(),flush=True)
            assert response.get('status')=='OPEN' and isinstance(response.get('flag'),str), 'Remote did not open'
            (ROOT/'flag.txt').write_text(response['flag']+'\n')
    else:
        for n in range(1,4):
            t=np.linspace(0,2*np.pi*n,128)
            q=np.rint(124*np.c_[np.cos(t),np.sin(t)])
            m.evaluate(q)
