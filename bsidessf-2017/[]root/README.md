# BsidesSF 2017 - []root (crypto, 250 pts)

>Our guy inside e-corp was able to get that packet capture of their backend PKI you asked for. Unfortunately it seems they're using TLS to protect the modulus fetch. Now, I have been told that the best crackers in the world can do this in 60 minutes. Unfortunately I need someone who can do it in 60 seconds.

>Note: Flag does not follow the "Flag:" format but is recognizable

>[e_corp_pki.pcapng](e_corp_pki.pcapng)

We are provided with a packet capture file containing a TLS exchange. Loading it up in Wireshark, we can quickly identify a TLS handshake, with a "server hello" message containing the server certificate, itself containing the RSA public key (modulus + public exponent):

   ![](https://i.imgur.com/qUVa28T.png)

We need to recover the private key by factoring the modulus. We used [Fermat's factorisation method](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method) to recover the two prime factors (script [here](e_corp_pki.pcapng)):

This quickly yielded values for `p` and `q`. Plugging those values into [rsatool](https://github.com/ius/rsatool), we were able to reconstruct the server's private key:

    python ./rsatool.py -p 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232019973 -q 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232018933 -e 31337 -o priv.key


    [...]
    
    Saving PEM as priv.key

The next step was to load this private key back into Wireshark to see decrypted TLS traffic. We could see a `GET /modulus` HTTP request with some form of ASCII art:

![](https://i.imgur.com/sNehdqd.png)

Nice ASCII art key we thought... But then we looked closely to the first non-zero bytes towards the end: `66 6c 61 67`. This looks like ASCII for "flag"! And indeed:

    >>> '66:6c:61:67:3a:77:68:65:6e:5f:73:6f:6c:76:69:6e:67:5f:70:72:6f:62:6c:65:6d:73:5f:64:69:67:5f:61:74:5f:74:68:65:5f:72:6f:6f:74:73:5f:69:6e:73:74:65:61:64:5f:6f:66:5f:6a:75:73:74:5f:68:61:63:6b:69:6e:67:5f:61:74:5f:74:68:65:5f:6c:65:61:76:65:73'.replace(':','').decode('hex')
    'flag:when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves'