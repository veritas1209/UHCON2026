#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <random>
#include <vector>
using namespace std;
static uint8_t M[0x5b10];
int s8(int off){return (int8_t)M[off];}
int i32(int off){int n;memcpy(&n,M+off,4);return n;}
int rnd128(int n){int a=abs(n),q=a/128,r=a%128; q+=(r>64||(r==64&&(q&1)));return n<0?-q:q;}
int rnd16(int n){int a=abs(n),q=a/16,r=a%16; q+=(r>8||(r==8&&(q&1)));return n<0?-q:q;}
using Q=array<array<int,2>,128>;
struct E {double loss=0;int dense,seg[8][2],global[2],hash[12],quality;};
double negpen(int n,double scale){return n<0?-n/scale:0;}
E eval(const Q&q,int phase){
  int z[256],sgn[256]; E e;
  for(int j=0;j<128;j++)for(int c=0;c<2;c++){
    z[2*j+c]=(39*j*j-99*j+(c?192:109)+(((j+c)&1)?-q[j][c]:q[j][c]))&255;
    sgn[2*j+c]=(int8_t)z[2*j+c];
  }
  int h[32];for(int k=0;k<32;k++){int acc=i32(0x2000+4*k);for(int j=0;j<256;j++)acc+=s8(k*256+j)*sgn[j];h[k]=clamp(rnd128(acc),0,127);}
  int logits[2]={i32(0x20c0),i32(0x20c4)};for(int k=0;k<32;k++)for(int c=0;c<2;c++)logits[c]+=s8(0x2080+c*32+k)*h[k];
  e.dense=logits[1]-logits[0]-i32(0x20c8);
  int seq[2][8][48];
  for(int rev=0;rev<2;rev++){
    int hidden[48]={0},nh[48];int key=0;
    for(int t=0;t<128;t++){
      int j=rev?127-t:t,off=0xa20*rev;
      if(t%16==0)key=((rev?0xa7:0x5d)^(53*(j/16)))&255;
      int a=M[0x20cc+512*rev+(z[2*j]^key^M[0x24cc+256*rev+2*j])];
      int b=M[0x21cc+512*rev+(z[2*j+1]^(((key<<3)|(key>>5))&255)^M[0x24cd+256*rev+2*j])];
      for(int k=0;k<48;k++){
        int acc=i32(0x302c+off+4*k)+s8(0x26cc+off+2*k)*(int8_t)a+s8(0x26cd+off+2*k)*(int8_t)b;
        for(int l=0;l<48;l++)acc+=s8(0x272c+off+k*48+l)*hidden[l];
        nh[k]=clamp(hidden[k]+rnd128(acc),0,127);
      }
      memcpy(hidden,nh,sizeof hidden);
      if((t+1)%16==0)memcpy(seq[rev][j/16],hidden,sizeof hidden);
      key=(key+17*t+29+(z[2*j]>>4)+3*(z[2*j+1]>>4))&255;
      key=(((key<<1)|(key>>7))^(a>>4)^(b>>3))&255;
    }
  }
  for(int j=0;j<8;j++){
    int feat[102];memcpy(feat,seq[0][j],48*sizeof(int));memcpy(feat+48,seq[1][j],48*sizeof(int));
    for(int c=0;c<2;c++){
      feat[96+c]=sgn[32*j+c];feat[98+c]=sgn[32*j+30+c];int sum=0;
      for(int k=0;k<16;k++)sum+=sgn[32*j+2*k+c];feat[100+c]=rnd16(sum);
    }
    int logit[3];for(int c=0;c<3;c++){int sum=i32(0x449c+(j*3+c)*4);for(int k=0;k<102;k++)sum+=s8(0x3b0c+j*306+c*102+k)*feat[k];logit[c]=sum;}
    for(int c=0;c<2;c++)e.seg[j][c]=logit[0]-logit[c+1]-i32(0x44fc+j*8+c*4);
  }
  int logit[3];for(int c=0;c<3;c++){
    int sum=i32(0x4e3c+c*4);for(int j=0;j<8;j++)for(int r=0;r<2;r++)for(int k=0;k<48;k++)sum+=s8(0x453c+c*768+j*96+r*48+k)*seq[r][j][k];logit[c]=sum;
  }
  for(int c=0;c<2;c++)e.global[c]=logit[0]-logit[c+1]-i32(0x4e48+c*4);
  for(int k=0;k<12;k++){
    int sum=0;for(int j=0;j<256;j++)sum+=s8(0x4e50+k*256+j)*z[j];sum=((sum%257)+257)%257;
    int d=abs(sum-i32(0x5a80+k*4));e.hash[k]=i32(0x5ae0+k*4)-min(d,257-d);
  }
  int qual=0,length=0,mn[2]={128,128},mx[2]={-128,-128};
  for(int j=0;j<128;j++)for(int c=0;c<2;c++){
    mn[c]=min(mn[c],q[j][c]);mx[c]=max(mx[c],q[j][c]);
    if(j){int d=abs(q[j][c]-q[j-1][c]);length+=d;qual+=max(0,d-128);}
    if(j>=2)qual+=max(0,abs(q[j][c]-2*q[j-1][c]+q[j-2][c])-56);
    if(j>=3)qual+=max(0,abs(q[j][c]-3*q[j-1][c]+3*q[j-2][c]-q[j-3][c])-80);
  }
  for(int c=0;c<2;c++)qual+=max(0,224-mx[c]+mn[c]);qual+=max(0,2500-length)+max(0,length-14000);e.quality=qual;
  e.loss=negpen(e.dense,15000);
  for(int j=0;j<8;j++)for(int c=0;c<2;c++)e.loss+=negpen(e.seg[j][c],8000);
  for(int c=0;c<2;c++)e.loss+=negpen(e.global[c],5000);
  if(phase>0)for(int k=0;k<12;k++)e.loss+=negpen(e.hash[k],phase==1?300:60);
  e.loss+=qual/30.;return e;
}
void report(E&e){printf("loss %.5f dense %d quality %d seg ",e.loss,e.dense,e.quality);for(auto&s:e.seg)printf("%d,%d ",s[0],s[1]);printf("global %d,%d hash ",e.global[0],e.global[1]);for(int k:e.hash)printf("%d ",k);puts("");fflush(stdout);}
void save(const Q&q){ofstream f("candidate.json");f<<"[";for(int j=0;j<128;j++){if(j)f<<",";f<<"["<<q[j][0]+3840<<","<<q[j][1]+3840<<"]";}f<<"]";}
int main(int argc,char**argv){
  ifstream f("model_decoded.bin",ios::binary);f.read((char*)M,sizeof M);
  mt19937 rng(argc>1?atoi(argv[1]):1);int phase=argc>2?atoi(argv[2]):0,its=argc>3?atoi(argv[3]):50000;
  Q q;for(int i=0;i<128;i++){double t=i*2*M_PI/127;q[i]={int(round(124*cos(t))),int(round(124*sin(t)))};}
  ifstream init("candidate.json");if(init){string s((istreambuf_iterator<char>(init)),{});int at=0;for(char&c:s)if(c=='['||c==']'||c==',')c=' ';char*p=s.data();for(int i=0;i<128;i++)for(int c=0;c<2;c++){q[i][c]=strtol(p,&p,10)-3840;}}
  E cur=eval(q,phase),best=cur;Q bestq=q;report(cur);
  for(int iter=0;iter<its;iter++){
    Q nq=q;int j=rng()%128,c=rng()%2;int delta=int(rng()%33)-16;
    int kind=rng()%10;
    if(kind<7)nq[j][c]=clamp(nq[j][c]+delta,-128,127);
    else if(kind<9){int radius=2+rng()%7;for(int k=max(0,j-radius);k<=min(127,j+radius);k++)nq[k][c]=clamp(nq[k][c]+int(round(delta*(1-abs(k-j)/double(radius+1)))),-128,127);}
    else {int end=min(128,j+1+int(rng()%16));for(int k=j;k<end;k++)nq[k][c]=clamp(nq[k][c]+delta,-128,127);}
    E next=eval(nq,phase);double temp=0.015+0.2*pow(1.-(iter%5000)/5000.,3);
    if(next.loss<cur.loss||uniform_real_distribution<double>(0,1)(rng)<exp((cur.loss-next.loss)/temp)){q=nq;cur=next;}
    if(next.loss<best.loss){best=next;bestq=nq;if(iter%10==0||best.loss==0){printf("iter %d ",iter);report(best);}save(bestq);}
    if(best.loss==0){report(best);save(bestq);return 0;}
    if(iter%5000==4999){q=bestq;cur=best;printf("checkpoint %d ",iter);report(best);}
  }
  save(bestq);report(best);
}
