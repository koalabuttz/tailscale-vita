use core::marker::PhantomData;

use aead::{generic_array::GenericArray, AeadInPlace};
use crypto_box::Tag;
use zerocopy::{FromBytes, IntoBytes, KnownLayout, TryFromBytes};

use crate::keys::{DiscoPrivateKey, DiscoPublicKey};
use crate::{message_type::MessageType, Error, Header, Message};

/// Marker indicating a [`Packet`] holds an encrypted payload.
pub enum Encrypted {}

/// Plaintext payload — type byte + version byte + message.
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Plaintext {
    ty: u8,
    version: u8,
    message: [u8],
}

impl Plaintext {
    pub const VERSION: u8 = 0;

    pub fn ty(&self) -> Option<MessageType> {
        self.ty.try_into().ok()
    }

    pub const fn size_for_message(payload_size: usize) -> usize {
        2 + payload_size
    }
}

/// AEAD-tagged payload — Poly1305 tag + ciphertext.
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct AeadTaggedPayload {
    tag: [u8; 16],
    payload: [u8],
}

impl AeadTaggedPayload {
    pub const fn size_for_payload(payload_size: usize) -> usize {
        16 + payload_size
    }
}

/// A disco packet, parameterized by encryption state.
#[derive(
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Packet<CryptState: ?Sized> {
    phantom: PhantomData<CryptState>,
    header: Header,
    payload: AeadTaggedPayload,
}

impl<CryptState> Packet<CryptState>
where
    CryptState: ?Sized,
{
    pub fn header(&self) -> &Header {
        &self.header
    }
}

impl Packet<Plaintext> {
    /// Initialize a plaintext packet in the given byte slice. The
    /// `init_msg` closure populates the message body. The slice must be
    /// sized exactly via [`Packet::size_for_message`].
    ///
    /// Header nonce + sender_pub are NOT set; they're written at
    /// encryption time in [`Packet::encrypt_in_place`].
    pub fn init_from_bytes<Msg>(
        b: &mut [u8],
        init_msg: impl FnOnce(&mut Msg),
    ) -> Result<&mut Self, Error>
    where
        Msg: ?Sized + Message + zerocopy::Immutable + TryFromBytes + IntoBytes + KnownLayout,
    {
        let s = Self::try_mut_from_bytes(b)?;

        let pt = Plaintext::mut_from_bytes(&mut s.payload.payload)?;
        pt.ty = Msg::TYPE as _;
        pt.version = 0;

        let msg = Msg::try_mut_from_bytes(&mut pt.message)?;
        init_msg(msg);

        s.validate()?;

        Ok(s)
    }

    /// Cast a slice to a plaintext packet without checking the type byte.
    ///
    /// # Safety
    /// The cast is safe; semantically, the type/version fields may
    /// disagree with the payload.
    pub unsafe fn from_bytes_unchecked(b: &[u8]) -> Result<&Self, Error> {
        Self::try_ref_from_bytes(b).map_err(From::from)
    }

    /// Mutable variant of [`Packet::from_bytes_unchecked`].
    ///
    /// # Safety
    /// Same caveats as [`Packet::from_bytes_unchecked`].
    pub unsafe fn from_bytes_unchecked_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        Self::try_mut_from_bytes(b).map_err(From::from)
    }

    /// Encrypt this packet in-place; returns a [`Packet<Encrypted>`].
    pub fn encrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
        receiver: &DiscoPublicKey,
        nonce: [u8; Header::NONCE_LEN],
    ) -> Result<&mut Packet<Encrypted>, Error> {
        let bx = crypto_box::SalsaBox::new(&receiver.into(), &secret.into());

        self.header.sender_pub = secret.public_key();
        self.header.nonce = nonce;

        let tag = bx
            .encrypt_in_place_detached(&GenericArray::from(nonce), &[], &mut self.payload.payload)
            .map_err(|_e| Error::CryptoFailed)?;

        self.payload.tag.copy_from_slice(tag.as_ref());

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;

        Ok(ret)
    }

    pub fn ty(&self) -> Option<MessageType> {
        self.plaintext()?.ty()
    }

    pub fn ty_raw(&self) -> Option<u8> {
        Some(self.plaintext()?.ty)
    }

    pub fn version(&self) -> Option<u8> {
        Some(self.plaintext()?.version)
    }

    pub fn as_msg<T>(&self) -> Option<&T>
    where
        T: ?Sized + Message + zerocopy::Immutable + zerocopy::KnownLayout + zerocopy::FromBytes,
    {
        let pt = self.plaintext()?;
        if pt.ty() != Some(T::TYPE) {
            return None;
        }
        T::ref_from_bytes(&pt.message).ok()
    }

    pub fn as_msg_mut<T>(&mut self) -> Option<&mut T>
    where
        T: ?Sized
            + Message
            + zerocopy::Immutable
            + zerocopy::KnownLayout
            + zerocopy::FromBytes
            + zerocopy::IntoBytes,
    {
        let pt = self.plaintext_mut()?;
        if pt.ty() != Some(T::TYPE) {
            return None;
        }
        T::mut_from_bytes(&mut pt.message).ok()
    }

    pub const fn size_for_message(message_size: usize) -> usize {
        size_of::<Header>()
            + AeadTaggedPayload::size_for_payload(Plaintext::size_for_message(message_size))
    }

    #[cfg(feature = "alloc")]
    pub fn vec_for_message(message_size: usize) -> alloc::vec::Vec<u8> {
        alloc::vec![0; Self::size_for_message(message_size)]
    }

    #[cfg(feature = "alloc")]
    pub fn box_for_message(message_size: usize) -> alloc::boxed::Box<[u8]> {
        Self::vec_for_message(message_size).into_boxed_slice()
    }

    pub fn validate(&self) -> Result<(), Error> {
        let pt = Plaintext::ref_from_bytes(&self.payload.payload)?;
        if pt.version != Plaintext::VERSION {
            return Err(Error::UnknownVersion);
        }
        Ok(())
    }

    fn plaintext(&self) -> Option<&Plaintext> {
        Plaintext::ref_from_bytes(&self.payload.payload).ok()
    }

    fn plaintext_mut(&mut self) -> Option<&mut Plaintext> {
        Plaintext::mut_from_bytes(&mut self.payload.payload).ok()
    }
}

impl Packet<Encrypted> {
    /// Cast bytes to an encrypted packet, validating header magic.
    pub fn from_encrypted_bytes(b: &[u8]) -> Result<&Self, Error> {
        let slf = Self::try_ref_from_bytes(b)?;
        slf.header.validate()?;
        Ok(slf)
    }

    /// Mutable variant.
    pub fn from_encrypted_bytes_mut(b: &mut [u8]) -> Result<&mut Self, Error> {
        let slf = Self::try_mut_from_bytes(b)?;
        slf.header.validate()?;
        Ok(slf)
    }

    pub const fn payload_bytes(&self) -> &[u8] {
        &self.payload.payload
    }

    /// Decrypt in-place; returns a [`Packet<Plaintext>`].
    pub fn decrypt_in_place(
        &mut self,
        secret: &DiscoPrivateKey,
    ) -> Result<&mut Packet<Plaintext>, Error> {
        crypto_box::SalsaBox::new(&self.header.sender_pub.into(), &secret.into())
            .decrypt_in_place_detached(
                &self.header.nonce.into(),
                &[],
                &mut self.payload.payload,
                Tag::from_slice(&self.payload.tag),
            )
            .map_err(|_e| Error::CryptoFailed)?;

        let bs = self.as_mut_bytes();
        let ret = Packet::mut_from_bytes(bs)?;
        ret.validate()?;

        Ok(ret)
    }
}
