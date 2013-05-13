#!/usr/bin/env python3
# ============================================================
# AutoCA - A tool for generating x509 certificates
# by Eric O'Connor
# ============================================================

import os,re,sys,subprocess,argparse,getpass,traceback
import json, tempfile, base64
from os import path

use_keyring=False
try:
    import keyring
    use_keyring=True
except:
    pass

# ------------------------------------------------------------
# x509 Request Configuration
# ------------------------------------------------------------

req_config='''
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
attributes = req_attributes
prompt = no
[ req_attributes ]
'''

req_config_dn='''
[ req_distinguished_name ]
C = {C}
ST = {ST}
L = {L}
O = {O}
OU = {OU}
CN = {CN}
emailAddress  = {emailAddress}
'''

req_config_v3='''
[ v3_req ]
subjectKeyIdentifier=hash
basicConstraints = CA:{CATF}
'''

# ------------------------------------------------------------
# JSON Configuration
# ------------------------------------------------------------

default_config={
    'global': {
        'umask': '0o007'
        },
    'DN': {
        'C': 'US',
        'ST': 'Massachusetts',
        'L': 'Boston',
        'O': 'Organization, Inc',
        'OU': 'Muppets',
        'emailAddress': 'support@organization.com',
        'CN': None
        },
    'ca': {
        'name': 'ca'
        },
    'certificates': {
        'cert': '{name}-cert.pem',
        'csr': '{name}-csr.pem',
        'key': '{name}-key.pem',
        'p12': '{name}.p12',
        'p12-passlen': 64,
        'expiration': 3650
        },
    'keys': {
        'algorithm': 'RSA',
        'curve': 'secp384r1',
        'rsa_bits': 4096,
        'paramfile': 'params.pem'
        }
    }

# ------------------------------------------------------------
# Python Functions
# ------------------------------------------------------------

def eprint(msg):
    print(msg, file=sys.stderr)

def norm(pth):
    return path.abspath(
        path.expandvars(
            path.expanduser(pth)))

def jnorm(*pths):
    return norm(path.join(*pths))

def generate_password(bits):
    ln=max(bits//8,1)
    with open('/dev/urandom','rb') as f:
        ret=base64.b32encode(f.read(ln)).lower().decode()
        return ret[:ret.index('=') if '=' in ret else len(ret)]

def fwrap(fn, value):
    iv=(value,)
    return lambda: fn(iv[0])

# ------------------------------------------------------------

def yesno(prompt):
    while True:
        x=input(prompt+' (yes/no): ')
        if re.match(r'^y(es?)?$',x):
            return True
        elif re.match(r'^no?$',x):
            return False
        else:
            print('please enter yes or no')

# ------------------------------------------------------------

def listpath(dir):
    return list(map(lambda x: path.join(dir,x), os.listdir(dir)))

# ------------------------------------------------------------

class TempFile:

    def __init__(self, mode='w+'):
        self.mode=mode

    def __enter__(self):
        self.f=tempfile.NamedTemporaryFile(self.mode)
        return self.f

    def __exit__(self, etype, value, traceback):
        if self.f:
            try:
                f.close()
            except:
                pass

# ------------------------------------------------------------

class PasswordPipe:

    def __init__(self, password):
        self.password=password

    def __enter__(self):
        self.r,self.w = os.pipe()
        with os.fdopen(self.w,'w') as f:
            print(self.password,end=None,file=f)
        return self

    def getfd(self):
        return self.r

    def __exit__(self, etype, value, traceback):
        try:
            os.close(self.r)
        except:
            pass
        try:
            os.close(self.w)
        except:
            pass

# ------------------------------------------------------------

def get_password(verify=False,prompt='password: ', minlen=None):
    while True:
        p=getpass.getpass(prompt=prompt)
        if minlen and len(p) < minlen:
            print('password must be >',minlen,'characters')
            continue
        if verify:
            v=getpass.getpass(prompt='please verify: ')
            if p==v:
                return p
            else:
                print('passwords did not match, retry...')
        else:
            return p

# ------------------------------------------------------------

def get_paths(base, authority, config):
    ret={}
    cert,key= \
        config['certificates']['cert'], \
        config['certificates']['key']
    nbase=jnorm(base,authority)
    ret['base']=nbase
    ret['cert']=jnorm(nbase,cert.format(name=authority))
    ret['key']=jnorm(nbase,key.format(name=authority))
    ret['leaves']=jnorm(nbase,'certs')
    ret['serial']=jnorm(ret['base'],'serial.txt')
    return ret

def ensure_paths(base, authority, config):
    ret=get_paths(base,authority,config)
    os.makedirs(ret['leaves'],mode=0o775, exist_ok=True)
    with open(ret['serial'],'w') as f:
        f.write('02')
    return ret

def get_inner_paths(ca_pths, config, simple):
    ret={}
    base=jnorm(ca_pths['leaves'],simple)
    certs=config['certificates']
    ret['base']=base
    ret['cert']=jnorm(base,certs['cert'].format(name=simple))
    ret['csr']=jnorm(base,certs['csr'].format(name=simple))
    ret['key']=jnorm(base,certs['key'].format(name=simple))
    ret['p12']=jnorm(base,certs['p12'].format(name=simple))
    return ret

def ensure_inner_paths(ca_pths, config, simple):
    ret=get_inner_paths(ca_pths, config, simple)
    os.makedirs(ret['base'],mode=0o755, exist_ok=True)
    return ret

# ------------------------------------------------------------
# Private Key Generation
# ------------------------------------------------------------

def genparams(params, curve):
    with open('/dev/null','w') as f:
        ps=subprocess.Popen(
            ['openssl','ecparam',
             '-out',params,
             '-name',curve],
            stdout=f,stderr=f,
            shell=False)
        return ps.wait()==0

# ------------------------------------------------------------

def genpkey(pth,config,paramfile,password=None):
    def _inner_genpkey(pp):
        with open('/dev/null','w') as f:
            args=['openssl','genpkey',
                  '-outform','PEM',
                  '-out',pth if pth else '/dev/stdout']
            if config['keys']['algorithm']=='EC' and paramfile:
                args.extend(['-paramfile',paramfile])
            elif config['keys']['algorithm']=='RSA':
                args.extend(['-algorithm','RSA',
                             '-pkeyopt','rsa_keygen_bits:{}'.format(
                            config['keys']['rsa_bits'])])
            if pp:
                args.extend(['-pass','fd:{}'.format(pp.getfd()),
                             '-aes256'])
            ps=subprocess.Popen(args,
                                stdout=None,
                                stderr=None,
                                close_fds=False,
                                shell=False)
            return ps.wait()==0
    if password:
        with PasswordPipe(password) as pp:
            return _inner_genpkey(pp)
    else:
        return _inner_genpkey(None)

# ------------------------------------------------------------

def is_password_required(pkey):
    if not path.exists(pkey):
        raise Exception('Key does not exist {}'.format(pkey))
    with open('/dev/null','w') as f:
        ps=subprocess.Popen(
            ['openssl','pkey',
             '-in',pkey,
             '-passin','pass:'],
            stdout=f,stderr=f,
            close_fds=False,
            shell=False)
        return ps.wait()==1

def test_password(pkey, password):
    if not path.exists(pkey) or not password:
        return False
    with open('/dev/null','w') as f:
        with PasswordPipe(password) as pp:
            ps=subprocess.Popen(
                ['openssl','pkey',
                 '-in',pkey,
                 '-passin','fd:{}'.format(pp.getfd())],
                stdout=f,stderr=f,
                close_fds=False,
                shell=False)
            return ps.wait()==0

# ------------------------------------------------------------
# Certificate Generation
# ------------------------------------------------------------

def build_req_string(is_ca, config, dn):
    global req_config, req_config_dn, req_config_v3
    ret=req_config
    dn_map=config['DN']
    for key,value in dn.items():
        if key in dn_map:
            dn_map[key]=value
    ret+=req_config_dn.format(**dn_map)
    catf='FALSE'
    if is_ca:
        catf='TRUE'
    ret+=req_config_v3.format(CATF=catf)
    return ret

# ------------------------------------------------------------

def gencsr(pths,dn,config,password,is_ca=False):
    def _inner_mkcsr(pp):
        with open('/dev/null','w') as f:
            with TempFile() as temp:
                temp.write(build_req_string(is_ca, config, dn))
                temp.seek(0)
                args=['openssl','req',
                      '-sha512','-new','-utf8','-batch',
                      '-key',pths['key'],
                      '-days',str(config['certificates']['expiration']),
                      '-config',temp.name]
                if is_ca:
                    args.extend(['-set_serial',str(1),
                                 '-x509',
                                 '-out',pths['cert']])
                else:
                    args.extend(['-out',pths['csr']])
                if pp:
                    args.extend(['-passin','fd:{}'.format(pp.getfd())])
                ps=subprocess.Popen(args,
                                    stdout=f,stderr=f,
                                    close_fds=False,
                                    shell=False)
                return ps.wait()==0
    if password:
        with PasswordPipe(password) as pp:
            return _inner_mkcsr(pp)
    else:
        return _inner_mkcsr(None)

# ------------------------------------------------------------

def signcsr(pths,ipths,config,password):
    def _inner_signcsr(pp):
        with open('/dev/null','w') as f:
            with TempFile() as temp:
                temp.write(build_req_string(False, config, {}))
                temp.seek(0)
                args=['openssl','x509',
                      '-in',ipths['csr'],
                      '-sha512','-req',
                      '-CA',pths['cert'],
                      '-CAkey',pths['key'],
                      '-CAserial',pths['serial'],
                      '-days',str(config['certificates']['expiration']),
                      '-out',ipths['cert'],
                      '-extfile',temp.name,
                      '-extensions','v3_req']
                if pp:
                    args.extend(['-passin','fd:{}'.format(pp.getfd())])
                ps=subprocess.Popen(args,
                                    stdout=f,stderr=f,
                                    close_fds=False,
                                    shell=False)
            return ps.wait()==0
    if password:
        with PasswordPipe(password) as pp:
            return _inner_signcsr(pp)
    else:
        return _inner_signcsr(None)

# ------------------------------------------------------------

def genpkcs12(pths, ipths, config, short, keypw, password):
    def _inner_genpkcs12(keypp, pp):
        with open('/dev/null','w') as f:
            args=['openssl','pkcs12',
                  '-export',
                  '-in',ipths['cert'],
                  '-inkey',ipths['key'],
                  '-out',ipths['p12'],
                  '-name',short,
                  '-certfile',pths['cert'],
                  '-passout','fd:{}'.format(keypp.getfd())
                  ]
            if pp:
                args.extend(['-passin','fd:{}'
                             .format(pp.getfd())])
            ps=subprocess.Popen(args,
                                stdout=None,stderr=None,
                                close_fds=False,
                                shell=False)
            return ps.wait()==0
    with PasswordPipe(password) as keypp:
        if password:
            with PasswordPipe(keypw) as pp:
                return _inner_genpkcs12(keypp, pp)
        else:
            return _inner_genpkcs12(None)

# ------------------------------------------------------------
# Keyring support functions

def keyring_lookup(*args):
    ls=[]
    for x in args:
        ls.append(re.sub(r'[^A-Za-z0-9.-_]+','',x))
    return '_'.join(ls)

def set_keyring(password, *args):
    global use_keyring
    if use_keyring:
        keyring.set_password('autoca', keyring_lookup(*args), password)

def get_keyring(*args):
    global use_keyring
    if use_keyring:
        return keyring.get_password('autoca',keyring_lookup(*args))

def del_keyring(*args):
    global use_keyring
    if use_keyring:
        return keyring.delete_password('autoca',keyring_lookup(*args))

# ------------------------------------------------------------

def set_umask(mask):
    if isinstance(mask, str) and \
            re.match(r'^0[ox][0-7]+$',mask):
        os.umask(eval(mask))
    elif isinstance(mask, int):
        os.umask(mask)

# ------------------------------------------------------------

def run():
    global default_config, req_config, use_keyring

    op_on_success=[]

    # base directory
    env_name='AUTOCA_DIR'
    if env_name in os.environ:
        ca_dir=norm(os.environ[env_name])
    else:
        ca_dir=norm('.')

    # parse args
    args=argparse.ArgumentParser(description='''
      AutoCA tool
    ''')
    args.add_argument('-c','--config',dest='config',
                      default='config.json',
                      help='config.json path')
    args.add_argument('-d','--dir',dest='target',
                      default=ca_dir,
                      help='base directory')
    args.add_argument('-p','--keyparams',dest='params',
                      help='openssl genpkey params file')
    args.add_argument('-o','--out',dest='out',
                      help='manual output file')
    args.add_argument('-s','--short',dest='short',
                      help='short name')
    args.add_argument('-a','--authority',dest='authority',
                      help='authority short name (such as "ca")')
    args.add_argument('--email',dest='email',
                      help='email address')
    args.add_argument('-n','--name',dest='cn',
                      help='common name')
    args.add_argument('-u','--unit',dest='unit',
                      help='org unit')
    args.add_argument('-e','--pass',action='store_true',
                      dest='password',
                      help='use password? (prompted on stdin)')
    args.add_argument('-r','--csr',dest='csr',
                      help='referenced csr')
    args.add_argument('op',
                      choices=['init','keygen','writeconfig',
                               'mkca','mkcert','signcsr','mkp12'],
                      help='action to perform')
    
    opts=args.parse_args()

    # normalize paths
    ca_dir=norm(opts.target)
    op=opts.op
    config_path=jnorm(ca_dir, opts.config)

    config=None
    # configuration loading
    if not path.exists(config_path):
        config=default_config
        set_umask(config['global']['umask'])
        if op!='writeconfig':
            config_path=jnorm(ca_dir,'./config.json')
            with open(config_path,'w') as f:
                json.dump(config,f,indent=True)
    else:
        with open(config_path) as f:
            config=json.load(f)
        set_umask(config['global']['umask'])

    algorithm=config['keys']['algorithm'].upper()
    config['keys']['algorithm']=algorithm

    params=None
    if algorithm=='EC':
        if opts.params:
            params=jnorm(ca_dir, opts.params)
        else:
            params=jnorm(ca_dir, config['keys']['paramfile'])

    if op!='writeconfig' and params:
        # generate params
        if not path.exists(params):
            params=jnorm(ca_dir, config['keys']['paramfile'])
            if not genparams(params, config['keys']['curve']):
                raise Exception('EC may not be supported (Fedora?)')

    authority=opts.authority or config['ca']['name']
    short=opts.short
    if not opts.short and opts.cn:
        short=re.sub(r'[^A-Za-z0-9.]+','', opts.cn)
    email=opts.email or config['DN']['emailAddress']
    cn=opts.cn
    unit=opts.unit or config['DN']['OU']
    password=opts.password
    out=norm(opts.out) if opts.out else None

    # perform operation
    if op=='keygen':
        if short:
            pth=jnorm(ca_dir,config['certificates']['key']
                      .format(name=short))
        elif out:
            pth=jnorm(ca_dir,out)
        else:
            raise Exception('keygen requires an output path')
        pw=None
        if password:
            pw=get_password(True)
        if not genpkey(pth,config,params,pw):
            print('Error generating key', file=sys.stderr)
            return

    elif op=='writeconfig':
        if not out:
            raise Exception('Supply an output file with --out')
        with open(out,'w') as f:
            json.dump(config,f,indent=True)

    elif op=='mkca':
        if not cn:
            raise Exception('Common Name required for mkca')
        pths=ensure_paths(ca_dir, authority, config)
        pw=None
        if password:
            pw=get_password(True, 'Password for CA key: ')
            set_keyring(pw,'CA',authority,'key')
        if not genpkey(pths['key'], config, params, pw):
            print('Error generating CA key', file=sys.stderr)
            return
        if not gencsr(pths,
                      {'CN':cn, 'OU': unit, 'emailAddress': email},
                      config,pw,True):
            print('Error generating CA cert', file=sys.stderr)
            return

    elif op=='mkcert':
        pths=get_paths(ca_dir,authority,config)
        if not path.exists(pths['leaves']):
            raise Exception('CA {} does not exist'.format(authority))
        ipths=ensure_inner_paths(pths, config, short)
        # password handling
        pw=None
        if password:
            pw=get_password(True, 'Password for new key: ')
            set_keyring(pw,'CA',authority,'CERT',short)
        if not genpkey(ipths['key'], config, params, pw):
            eprint('Error generating key')
            return
        # create csr
        if not gencsr(ipths,
                      {'CN':cn, 'OU': unit, 'emailAddress': email},
                      config,pw):
            eprint('Error generating CSR')
            return
        # sign certificate
        ca_pw=None
        if is_password_required(pths['key']):
            ca_pw=get_keyring('CA',authority,'key')
            valid=test_password(pths['key'], ca_pw)
            if ca_pw and not valid:
                del_keyring('CA',authority,'key')
            if not valid:
                ca_pw=get_password(False, 'Password for CA key: ')
                op_on_success.append(fwrap(
                        lambda x: set_keyring(
                            x[0],'CA',x[1],'key'),
                        [pw,authority]))
        if not signcsr(pths, ipths, config, ca_pw):
            eprint('Error creating certificate')
            return
        else:
            for op in op_on_success:
                op()

    elif op=='mkp12':
        pths=get_paths(ca_dir, authority, config)
        if not path.exists(pths['leaves']):
            raise Exception('CA {} does not exist'.format(authority))
        ipths=ensure_inner_paths(pths, config, short)
        # password handling
        pw,p12pw=None,None
        if is_password_required(ipths['key']):
            pw=get_keyring('CA',authority,'CERT',short)
            if not pw:
                pw=get_password(False, 'Password for key: ')
                op_on_success.append(fwrap(
                        lambda x: set_keyring(
                            x[0],'CA',x[1],'CERT',x[2]),
                        [pw,authority,short]))
        if password:
            p12pw=get_password(True, 'Password for PKCS12: ')
        else:
            genlen=config['certificates']['p12-passlen'] or 64
            p12pw=generate_password(genlen)
            print(p12pw)
        if not genpkcs12(pths, ipths, config, short, pw, p12pw):
            eprint('Error generating pkcs12')
            return
        else:
            for op in op_on_success:
                op()

# ------------------------------------------------------------

if __name__=='__main__':
    try:
        run()
    except Exception as e:
        traceback.print_exc()
        print('error:',e)

# ------------------------------------------------------------
# EOF
# ------------------------------------------------------------
