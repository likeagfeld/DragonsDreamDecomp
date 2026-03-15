import struct
def d(insn, pc):
    n=(insn>>8)&0xF;m=(insn>>4)&0xF;dd=insn&0xF;imm=insn&0xFF;top=(insn>>12)&0xF
    if insn==0x0009:return 'nop'
    if insn==0x000B:return 'rts'
    if insn==0x002B:return 'rte'
    if top==0:
        sub=insn&0xF
        if sub==2:
            if m==0:return 'stc SR,r%d'%n
            if m==1:return 'stc GBR,r%d'%n
        if sub==3:
            if m==0:return 'bsrf r%d'%n
            if m==2:return 'braf r%d'%n
        if sub==4:return 'mov.b r%d,@(r0,r%d)'%(m,n)
        if sub==5:return 'mov.w r%d,@(r0,r%d)'%(m,n)
        if sub==6:return 'mov.l r%d,@(r0,r%d)'%(m,n)
        if sub==7:return 'mul.l r%d,r%d'%(m,n)
        if insn==0x0008:return 'clrt'
        if insn==0x0018:return 'sett'
        if sub==9:
            if insn==0x0019:return 'div0u'
            return 'movt r%d'%n
        if sub==0xA:
            if m==0:return 'sts MACH,r%d'%n
            if m==1:return 'sts MACL,r%d'%n
            if m==2:return 'sts PR,r%d'%n
        if sub==0xC:return 'mov.b @(r0,r%d),r%d'%(m,n)
        if sub==0xD:return 'mov.w @(r0,r%d),r%d'%(m,n)
        if sub==0xE:return 'mov.l @(r0,r%d),r%d'%(m,n)
        return 'op0_%04x'%insn
    if top==1:return 'mov.l r%d,@(%d,r%d)'%(m,dd*4,n)
    if top==2:
        sub=insn&0xF
        t={0:'mov.b',1:'mov.w',2:'mov.l',4:'mov.b -',5:'mov.w -',6:'mov.l -',7:'div0s',8:'tst',9:'and',10:'xor',11:'or',12:'cmp/str',13:'xtrct',14:'mulu.w',15:'muls.w'}
        if sub in t:
            op=t[sub]
            if sub<=2:return '%s r%d,@r%d'%(op,m,n)
            if sub<=6:return '%s r%d,@-r%d'%(op.replace(' -',''),m,n)
            return '%s r%d,r%d'%(op,m,n)
        return 'op2_%04x'%insn
    if top==3:
        sub=insn&0xF
        ops={0:'cmp/eq',2:'cmp/hs',3:'cmp/ge',4:'div1',5:'dmulu.l',6:'cmp/hi',7:'cmp/gt',8:'sub',10:'subc',11:'subv',12:'add',13:'dmuls.l',14:'addc',15:'addv'}
        if sub in ops:return '%s r%d,r%d'%(ops[sub],m,n)
        return 'op3_%04x'%insn
    if top==4:
        s4=insn&0xF;s8=(insn>>4)&0xF
        if s4==0:
            if s8==0:return 'shll r%d'%n
            if s8==1:return 'dt r%d'%n
            if s8==2:return 'shal r%d'%n
        if s4==1:
            if s8==0:return 'shlr r%d'%n
            if s8==1:return 'cmp/pz r%d'%n
            if s8==2:return 'shar r%d'%n
        if s4==2:
            if s8==0:return 'sts.l MACH,@-r%d'%n
            if s8==1:return 'sts.l MACL,@-r%d'%n
            if s8==2:return 'sts.l PR,@-r%d'%n
        if s4==4:
            if s8==0:return 'rotl r%d'%n
            if s8==2:return 'rotcl r%d'%n
        if s4==5:
            if s8==0:return 'rotr r%d'%n
            if s8==1:return 'cmp/pl r%d'%n
            if s8==2:return 'rotcr r%d'%n
        if s4==6:
            if s8==0:return 'lds.l @r%d+,MACH'%n
            if s8==1:return 'lds.l @r%d+,MACL'%n
            if s8==2:return 'lds.l @r%d+,PR'%n
        if s4==8:
            if s8==0:return 'shll2 r%d'%n
            if s8==1:return 'shll8 r%d'%n
            if s8==2:return 'shll16 r%d'%n
        if s4==9:
            if s8==0:return 'shlr2 r%d'%n
            if s8==1:return 'shlr8 r%d'%n
            if s8==2:return 'shlr16 r%d'%n
        if s4==0xA:
            if s8==0:return 'lds r%d,MACH'%n
            if s8==1:return 'lds r%d,MACL'%n
            if s8==2:return 'lds r%d,PR'%n
        if s4==0xB:
            if s8==0:return 'jsr @r%d'%n
            if s8==1:return 'tas.b @r%d'%n
            if s8==2:return 'jmp @r%d'%n
        if s4==0xE:
            if s8==0:return 'ldc r%d,SR'%n
            if s8==1:return 'ldc r%d,GBR'%n
            if s8==2:return 'ldc r%d,VBR'%n
        return 'op4_%04x'%insn
    if top==5:return 'mov.l @(%d,r%d),r%d'%(dd*4,m,n)
    if top==6:
        sub=insn&0xF
        t={0:'mov.b @',1:'mov.w @',2:'mov.l @',3:'mov ',4:'mov.b @+',5:'mov.w @+',6:'mov.l @+',7:'not ',8:'swap.b ',9:'swap.w ',10:'negc ',11:'neg ',12:'extu.b ',13:'extu.w ',14:'exts.b ',15:'exts.w '}
        if sub in t:
            op=t[sub]
            if sub<=2:return '%sr%d,r%d'%(op,m,n)
            if sub==3:return '%sr%d,r%d'%(op,m,n)
            if sub<=6:return '%sr%d+,r%d'%(op.replace('+',''),m,n)  
            return '%sr%d,r%d'%(op,m,n)
        return 'op6_%04x'%insn
    if top==7:
        simm=imm if imm<128 else imm-256
        return 'add #%d,r%d'%(simm,n)
    if top==8:
        sub=(insn>>8)&0xF;simm8=imm if imm<128 else imm-256;rm=(insn>>4)&0xF;d4=insn&0xF
        if sub==0:return 'mov.b r0,@(%d,r%d)'%(d4,rm)
        if sub==1:return 'mov.w r0,@(%d,r%d)'%(d4*2,rm)
        if sub==4:return 'mov.b @(%d,r%d),r0'%(d4,rm)
        if sub==5:return 'mov.w @(%d,r%d),r0'%(d4*2,rm)
        if sub==8:return 'cmp/eq #%d,r0'%simm8
        if sub==9:return 'bt 0x%08X'%(pc+4+simm8*2)
        if sub==0xB:return 'bf 0x%08X'%(pc+4+simm8*2)
        if sub==0xD:return 'bt/s 0x%08X'%(pc+4+simm8*2)
        if sub==0xF:return 'bf/s 0x%08X'%(pc+4+simm8*2)
        return 'op8_%04x'%insn
    if top==9:
        target=pc+4+(insn&0xFF)*2
        return 'mov.w @(0x%08X),r%d'%(target,n)
    if top==0xA:
        disp=insn&0xFFF
        if disp>=0x800:disp-=0x1000
        return 'bra 0x%08X'%(pc+4+disp*2)
    if top==0xB:
        disp=insn&0xFFF
        if disp>=0x800:disp-=0x1000
        return 'bsr 0x%08X'%(pc+4+disp*2)
    if top==0xC:
        sub=(insn>>8)&0xF
        if sub==7:return 'mova @(0x%08X),r0'%((pc&0xFFFFFFFC)+4+imm*4)
        if sub==8:return 'tst #%d,r0'%imm
        if sub==9:return 'and #%d,r0'%imm
        if sub==0xA:return 'xor #%d,r0'%imm
        if sub==0xB:return 'or #%d,r0'%imm
        return 'opC_%04x'%insn
    if top==0xD:
        target=(pc&0xFFFFFFFC)+4+(insn&0xFF)*4
        return 'mov.l @(0x%08X),r%d'%(target,n)
    if top==0xE:
        simm=imm if imm<128 else imm-256
        return 'mov #%d,r%d'%(simm,n)
    return 'unk_%04x'%insn

with open(chr(68)+chr(58)+chr(47)+chr(68)+chr(114)+chr(97)+chr(103)+chr(111)+chr(110)+chr(115)+chr(68)+chr(114)+chr(101)+chr(97)+chr(109)+chr(68)+chr(101)+chr(99)+chr(111)+chr(109)+chr(112)+chr(47)+chr(101)+chr(120)+chr(116)+chr(114)+chr(97)+chr(99)+chr(116)+chr(101)+chr(100)+chr(47)+chr(48)+chr(46)+chr(66)+chr(73)+chr(78),'rb') as f:
    f.seek(0x0323C8)
    data=f.read(0x600)
base=0x060423C8
i=0
while i<len(data)-1:
    insn=struct.unpack(chr(62)+chr(72),data[i:i+2])[0]
    addr=base+i
    print('  %08X: %04X  %s'%(addr,insn,d(insn,addr)))
    i+=2
