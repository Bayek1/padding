import sys
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Cipher import Blowfish
from Crypto.Cipher import CAST
from Crypto.Cipher import ARC2
import binascii

# 用于加密/解密的密钥
# 演示poc，需要密钥
ENCKEY = 'abcdefgh'

def main(args):
  print("=== Padding Oracle Attack ===")

  ########################################

  # 自己配置这个部分
  iv = '12345678'
  plain = 'aaaaaaaaaaaaaaaaX'
  plain_want = "opaas"
  # 选择密码：blowfish/AES/DES/DES3/CAST/ARC2 

  cipher = "blowfish"

  ########################################

  block_size = 8
  if cipher.lower() == "aes": #lower() 方法转换字符串中所有大写字符为小写
    block_size = 16
  if len(iv) != block_size: #CBC模式初始化向量IV大小等于一个分组长度
    print("[-] IV 必须是 "+str(block_size)+" 字节长（与块大小相同）!")
    return False

  ######################################### #加密
  print("=== 生成密文 ===") #加密过程
  
  ciphertext = encrypt(plain, iv, cipher)

  if not ciphertext: #判定密文是否生成，若无则结束并报错
    print("[-] 加密错误!")
    return False
  
  print("[+] 明文是: "+plain)
  print("[+] IV是: "+hex_s(iv))
  print("[+] 密文是: "+ hex_s(ciphertext))

  ########################################## #Padding Oracle解密过程
  print("\n=== 开始Padding Oracle解密 ===")
  print("\n[+] 选择密码: "+cipher.upper()) #upper() 方法将字符串中的小写字母转为大写字母

  guess = padding_oracle_decrypt(cipher, ciphertext, iv, block_size)

  if guess:
    print("[+] 猜测中间值为: "+hex_s(guess["intermediary"])) #intermediary value(密文解密后的结果)
    print("[+] 明文=中间值 xor IV") #异或
    print("[+] 猜测明文为: "+guess["plaintext"])
    print("\n")

    if plain_want:
      print("=== 开始Padding Oracle加密 ===") #Padding Oracle加密过程
      print("[+] 明文要加密的是: "+plain_want)
      print("[+] 选择密码: "+cipher.upper())
 
      en = padding_oracle_encrypt(cipher, ciphertext, plain_want, iv, block_size)

      if en:
        print("[+] 加密成功!")
        print("[+] 你要的密文: "+hex_s(en[block_size:]))
        print("[+] IV 是: "+hex_s(en[:block_size]))
        print("\n=== 验证自定义加密结果 ===") #验证加密结果
        print("[+] 解密密文 '"+ hex_s(en[block_size:]) +" 是:")
        
        de = decrypt(en[block_size:], en[:block_size], cipher)
        if de == add_PKCS7_padding(plain_want, block_size):
          print(de)
          print("[+] 对了!")
        else:
          print("[-] 出错了!")
          return False

    return True
  else:
    return False

def padding_oracle_encrypt(cipher, ciphertext, plaintext, iv, block_size=8):

  # 最后一个块

  guess_cipher = ciphertext[0-block_size:] 

  plaintext = add_PKCS7_padding(plaintext, block_size)

  print("[*] 填充后，明文变为: "+hex_s(plaintext))
  print("\n")

  block = len(plaintext)

  iv_nouse = iv # 这里没用，事实上只需要中间人

  prev_cipher = ciphertext[0-block_size:] # 用最后一个密码块初始化，prev_cipher为上一个密文

  while block > 0:
    # 我们需要中间值
    tmp = padding_oracle_decrypt_block(cipher, prev_cipher, iv_nouse, block_size, debug=False)

    # 计算IV，IV是前一个块的密文
    prev_cipher = xor_str(plaintext[block-block_size:block], tmp["intermediary"])#异或函数

    #保存结果
    guess_cipher = prev_cipher + guess_cipher
    block = block - block_size

  return guess_cipher

#主函数里加密过程中的加密函数
def padding_oracle_decrypt(cipher, ciphertext, iv, block_size=8, debug=True):

  # 把密码分块，逐块操作密文
  cipher_block = fen_cipher_block(ciphertext, block_size)
  if cipher_block:#满足条件则成功分块，不满足则说明密文快大小不正确
    result = {}
    result["intermediary"] = ''#中间值
    result["plaintext"] = ''   #明文

    counter = 0

    for c in cipher_block:
      if debug:
        print("[*] 现在尝试解密块 "+str(counter))
        print("[*] 块 "+str(counter)+"的密文是: "+hex_s(c))
        print("\n")
      
      # padding oracle到每一个块
      guess = padding_oracle_decrypt_block(cipher, c, iv, block_size, debug)

      if guess:
        iv = c
        result["intermediary"] += guess["intermediary"]
        result["plaintext"] += guess["plaintext"]

        if debug:
          print("\n[+] 块 "+str(counter)+" 解密!")
          print("[+] 中间值是: "+hex_s(guess["intermediary"]))
          print("[+] 明文块 "+str(counter)+" 是: "+guess["plaintext"])
          print("\n")
        counter = counter+1
      else:
        print("[-] padding oracle解密错误!")       
        return False

    return result

  else:
    print("[-] 密文的块大小不正确!")
    return False

#填充到每一个块的函数
def padding_oracle_decrypt_block(cipher, ciphertext, iv, block_size=8, debug=True):
  result = {}
  plain = '' #初始化字符串
  intermediary = []  # 用来保存中间值的列表

  iv_p = [] # 列出我们找到的IV，在change函数中

  for i in range(1, block_size+1):
    iv_try = []
    iv_p = change_iv(iv_p, intermediary, i) #change_iv函数表示：通过Padding Oracle找到的IV字节并保存的列表

    # 构造IV
    # iv = \x00...(几个0字节) + \x0e(原始字节) + \xdc...(我们找到的IV字节)

    for k in range(0, block_size-i):
      iv_try.append(b"\x00") #append()方法用于在列表末尾添加新的对象。

    # 破解iv字节 for padding oracle
    # 破解1个字节，然后附加其余字节

    iv_try.append(b"\x00")

    for b in range(0,256):
      iv_tmp = iv_try
      iv_tmp[len(iv_tmp)-1] = chr(b)
      iv_tmp_s = ''.join("%s" % ch for ch in iv_tmp)#join()用于将序列中的元素以指定的字符连接生成一个新的字符串。

      # 附加IV的结果，我们只计算它，保存在IV_p中
      for p in range(0,len(iv_p)):
        iv_tmp_s += iv_p[len(iv_p)-1-p]

      # 在真正的攻击中，必须替换这个部分来触发解密程序
      #输出十六进制数hex_s(iv_tmp_s) # for debug
      plain = decrypt(ciphertext, iv_tmp_s, cipher)

      #输出十六进制数hex_s(plain) # for debug
      # 成了!

      # 在真正的攻击中，必须将此部分替换为填充错误判断
      if check_PKCS7_padding(plain, i):#padding验证（padding oracle中很重要的一个步骤）
        if debug:
          print("[*] 试试 IV: "+hex_s(iv_tmp_s))
          print("[*] 找到 padding oracle: " + hex_s(plain))

        iv_p.append(chr(b)) #append()方法用于在列表末尾添加新的对象
        intermediary.append(chr(b ^ i))# “^”符号表示：按位异或运算符：当两对应的二进位相异时，结果为1
        break

  plain = ''#初始化字符串

  for ch in range(0, len(intermediary)):
    plain += chr( ord(intermediary[len(intermediary)-1-ch]) ^ ord(iv[ch]) )# “^”符号表示按位异或运算符，当两对应的二进位相异时，结果为1
    #ord() 函数是 chr() 函数（对于 8 位的 ASCII 字符串）的配对函数，它以一个字符串（Unicode 字符）作为参数，
    # 返回对应的 ASCII 数值，或者 Unicode 数值。

  result["plaintext"] = plain
  result["intermediary"] = ''.join("%s" % ch for ch in intermediary)[::-1] #join()用于将序列中的元素以指定的字符连接生成一个新的字符串。
  return result

# 将通过Padding Oracle找到的IV字节保存到列表中
def change_iv(iv_p, intermediary, p):
  for i in range(0,len(iv_p)):
    iv_p[i] = chr(ord(intermediary[i]) ^ p) # “^”符号表示：按位异或运算符，当两对应的二进位相异时，结果为1
    #ord() 函数是 chr() 函数（对于 8 位的 ASCII 字符串）的配对函数，它以一个字符串（Unicode 字符）作为参数，
    # 返回对应的 ASCII 数值，或者 Unicode 数值。

  return iv_p  

#加密过程中的密文分块函数
def fen_cipher_block(ciphertext, block_size=8):
  if len(ciphertext) % block_size != 0:
    return False

  result = []

  length = 0 #初始化
  while length < len(ciphertext):
    result.append(ciphertext[length:length+block_size]) #append()方法用于在列表末尾添加新的对象
    length += block_size
  return result

def check_PKCS7_padding(plain, p):#验证结果是否与PkCS7相符

  if len(plain) % 8 != 0:
    return False

  # 转换字符串
  plain = plain[::-1] #字符串反转[::-1]
  ch = 0    #初始化
  found = 0 #初始化
  while ch < p:
    if plain[ch] == chr(p):
      found += 1
    ch += 1 

  if found == p:
    return True
  else:
    return False

def add_PKCS7_padding(plaintext, block_size):
  
  s = ''#初始化
  if len(plaintext) % block_size == 0:
    return plaintext
  if len(plaintext) < block_size:
    padding = block_size - len(plaintext)
  else:
    padding = block_size - (len(plaintext) % block_size)
  for i in range(0, padding):
    plaintext += chr(padding)
  return plaintext

def decrypt(ciphertext, iv, cipher):#加密过程中的解密函数
  
  # 我们只需要填充错误本身，而不是key
  # 在真正的攻击中，可以触发解密程序
 
  key = ENCKEY
  key = key.encode('utf-8')

  if cipher.lower() == "des":
    o = DES.new(key, DES.MODE_CBC,iv)

  elif cipher.lower() == "aes":
    o = AES.new(key, AES.MODE_CBC,iv)

  elif cipher.lower() == "des3":
    o = DES3.new(key, DES3.MODE_CBC,iv)

  elif cipher.lower() == "blowfish":
    o = Blowfish.new(key, Blowfish.MODE_CBC,iv)

  elif cipher.lower() == "cast":
    o = CAST.new(key, CAST.MODE_CBC,iv)

  elif cipher.lower() == "arc2":
    o = ARC2.new(key, ARC2.MODE_CBC,iv)

  else:
    return False

  if len(iv) % 8 != 0:
    return False

  if len(ciphertext) % 8 != 0:
    return False

  return o.decrypt(ciphertext)

def encrypt(plaintext, iv, cipher):#最初加密时的加密函数
 
  key = ENCKEY
  key = key.encode('utf-8')

  if cipher.lower() == "des":
    if len(key) != 8:
      print("[-] DES 密钥长度为8位!")
      return False
    o = DES.new(key, DES.MODE_CBC,iv)

  elif cipher.lower() == "aes":
    if len(key) != 16 and len(key) != 24 and len(key) != 32:
      print("[-] AES 密钥长度为16/24/32位!")
      return False
    o = AES.new(key, AES.MODE_CBC,iv)

  elif cipher.lower() == "des3":
    if len(key) != 16:
      print("[-]  DES3 密钥长度为16位!")
      return False
    o = DES3.new(key, DES3.MODE_CBC,iv)

  elif cipher.lower() == "blowfish":
    o = Blowfish.new(key, Blowfish.MODE_CBC,iv)
  
  elif cipher.lower() == "cast":
    o = CAST.new(key, CAST.MODE_CBC,iv)

  elif cipher.lower() == "arc2":
    o = ARC2.new(key, ARC2.MODE_CBC,iv)

  else:
    return False

  plaintext = add_PKCS7_padding(plaintext, len(iv))  

  return o.encrypt(plaintext)

def xor_str(a,b):#Padding Oracle加密函数中的异或运算

  if len(a) != len(b):#两者长度必须相等，不然无法进行异或运算
    return False

  c = ''

  for i in range(0, len(a)):
    c += chr( ord(a[i]) ^ ord(b[i]) )# ASCII 数值的异或运算操作
  return c

def hex_s(str):#十六进制转化

  re = ''
  for i in range(0,len(str)):
    re += "\\x"+binascii.b2a_hex(str[i])
  return re

if __name__ == "__main__":

        main(sys.argv)