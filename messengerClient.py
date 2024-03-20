#!/usr/bin/env python3
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pickle
import os

SALT = os.urandom(16)


class State:
    def __init__(self, DHs, DHr, RK):
        self.comm_first = True
        self.DHs = DHs
        self.DHr = DHr
        self.CKs = None
        self.CKr = None
        self.RK = RK
        self.initial_key = None


class MessengerClient:
    """Messenger client klasa

    Slobodno mijenjajte postojeće atribute i dodajte nove kako smatrate
    prikladnim.
    """

    def __init__(self, username, ca_pub_key):
        """Inicijalizacija klijenta

        Argumenti:
        username (str) -- ime klijenta
        ca_pub_key     -- javni ključ od CA (certificate authority)

        """
        self.username = username
        self.ca_pub_key = ca_pub_key
        # Aktivne konekcije s drugim klijentima
        self.conns = {}
        # Inicijalni Diffie-Hellman par ključeva iz metode `generate_certificate`
        self.dh_key_pair = ()

    def generate_certificate(self):
        """Generira par Diffie-Hellman ključeva i vraća certifikacijski objekt

        Metoda generira inicijalni Diffie-Hellman par kljuceva; serijalizirani
        javni kljuc se zajedno s imenom klijenta postavlja u certifikacijski
        objekt kojeg metoda vraća. Certifikacijski objekt moze biti proizvoljan (npr.
        dict ili tuple). Za serijalizaciju kljuca mozete koristiti
        metodu `public_bytes`; format (PEM ili DER) je proizvoljan.

        Certifikacijski objekt koji metoda vrati bit će potpisan od strane CA te
        će tako dobiveni certifikat biti proslijeđen drugim klijentima.

        """

        private_key = ec.generate_private_key(ec.SECP384R1())
        public_key = private_key.public_key()

        serialized_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        self.dh_key_pair = (private_key, public_key)

        return {"name": self.username, "serialized_public": serialized_public}

    def receive_certificate(self, cert, signature):
        """Verificira certifikat klijenta i sprema informacije o klijentu (ime
            i javni ključ)

        Argumenti:
        cert      -- certifikacijski objekt
        signature -- digitalni potpis od `cert`

        Metoda prima certifikacijski objekt (koji sadrži inicijalni
        Diffie-Hellman javni ključ i ime klijenta) i njegov potpis kojeg
        verificira koristeći javni ključ od CA i, ako je verifikacija uspješna,
        sprema informacije o klijentu (ime i javni ključ). Javni ključ od CA je
        spremljen prilikom inicijalizacije objekta.

        """
        name_client = cert["name"]
        pk_client = cert["serialized_public"]
        pk_client = serialization.load_pem_public_key(pk_client, None)

        initial_key = self.dh_key_pair[0].exchange(ec.ECDH(), pk_client)

        self.ca_pub_key.verify(signature, pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))

        self.conns[name_client] = State(
            DHs=self.dh_key_pair[0], DHr=pk_client, RK=initial_key
        )

    def send_message(self, username, message):
        """Slanje poruke klijentu

        Argumenti:
        message  -- poruka koju ćemo poslati
        username -- klijent kojem šaljemo poruku `message`

        Metoda šalje kriptiranu poruku sa zaglavljem klijentu s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da klijent posjeduje vaš.
        Ako već prije niste komunicirali, uspostavite sesiju tako da generirate
        nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada šaljete poruku napravite `ratchet` korak u `sending`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji).  S novim
        `sending` ključem kriptirajte poruku koristeći simetrični kriptosustav
        AES-GCM tako da zaglavlje poruke bude autentificirano.  Ovo znači da u
        zaglavlju poruke trebate proslijediti odgovarajući inicijalizacijski
        vektor.  Zaglavlje treba sadržavati podatke potrebne klijentu da
        derivira novi ključ i dekriptira poruku.  Svaka poruka mora biti
        kriptirana novim `sending` ključem.

        Metoda treba vratiti kriptiranu poruku zajedno sa zaglavljem.

        """
        if username not in self.conns:
            raise Exception("Korisnik ne postoji")
        state = self.conns[username]
        if state.comm_first:
            output = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=state.RK,
                info=None,
            ).derive(state.DHs.exchange(ec.ECDH(), state.DHr))
            state.RK, state.CKs = output[0:16], output[16:32]
            state.comm_first = False

        curr_send_key = state.CKs
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32 + 12,
            salt=SALT,
            info=None,
        )

        key = hkdf.derive(curr_send_key)

        state.CKs = key[:16]

        mk = key[16:32]

        iv = key[32:]

        dh_public_key = state.DHs.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        aesgcm = AESGCM(mk)
        ct = aesgcm.encrypt(iv, message.encode("utf-8"), None)

        return iv, dh_public_key, ct

    def receive_message(self, username, message):
        """Primanje poruke od korisnika

        Argumenti:
        message  -- poruka koju smo primili
        username -- klijent koji je poslao poruku

        Metoda prima kriptiranu poruku od klijenta s imenom `username`.
        Pretpostavite da već posjedujete certifikacijski objekt od klijenta
        (dobiven pomoću `receive_certificate`) i da je klijent izračunao
        inicijalni `root` ključ uz pomoć javnog Diffie-Hellman ključa iz vašeg
        certifikata.  Ako već prije niste komunicirali, uspostavite sesiju tako
        da generirate nužne `double ratchet` ključeve prema specifikaciji.

        Svaki put kada primite poruku napravite `ratchet` korak u `receiving`
        lanacu (i `root` lanacu ako je potrebno prema specifikaciji) koristeći
        informacije dostupne u zaglavlju i dekriptirajte poruku uz pomoć novog
        `receiving` ključa. Ako detektirate da je integritet poruke narušen,
        zaustavite izvršavanje programa i generirajte iznimku.

        Metoda treba vratiti dekriptiranu poruku.

        """

        if username not in self.conns:
            raise Exception("Korisnik ne postoji")
        state = self.conns[username]

        iv, dh_public_key, ct = message

        if (
            state.DHr.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            != dh_public_key
        ) and state.comm_first:
            raise Exception("!!!")

        if state.comm_first or (
            state.DHr.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            != dh_public_key
        ):
            state.comm_first = False

            state.DHr = serialization.load_pem_public_key(dh_public_key)
            output = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=state.RK,
                info=None,
            ).derive(state.DHs.exchange(ec.ECDH(), state.DHr))
            state.RK, state.CKr = output[0:16], output[16:32]

            state.DHs = ec.generate_private_key(ec.SECP384R1())
            output = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=state.RK,
                info=None,
            ).derive(state.DHs.exchange(ec.ECDH(), state.DHr))
            state.RK, state.CKs = output[0:16], output[16:32]

        curr_send_key = state.CKr
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            info=None,
        )

        key = hkdf.derive(curr_send_key)

        state.CKr = key[:16]

        mk = key[16:32]

        aesgcm = AESGCM(mk)
        plaintext = aesgcm.decrypt(iv, ct, None).decode("utf-8")

        return plaintext


def main():
    pass


if __name__ == "__main__":
    main()
