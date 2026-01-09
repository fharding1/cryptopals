extern crate aes;
extern crate cipher;
extern crate num_bigint;

use aes::Aes128;
use rand::{rngs::StdRng,SeedableRng,RngCore};
use cipher::{BlockEncrypt,Block,generic_array::GenericArray,KeyInit,BlockSizeUser};

struct CTRKeyStream<C>
where
    C: BlockEncrypt + KeyInit
{
    cipher: C,
    nonce: u64,
    ctr: u64,
}

impl <C: BlockEncrypt + KeyInit> CTRKeyStream<C> {
    fn new(key: &[u8], nonce: u64) -> Result<Self, cipher::InvalidLength> {
        let cipher = C::new(GenericArray::from_slice(key));
        Ok(Self { cipher: cipher, nonce: nonce, ctr: 0})
    }
}
        
impl<C: BlockEncrypt + KeyInit> Iterator for CTRKeyStream<C>{
    type Item = Block<C>;

    fn next(&mut self) -> Option<Self::Item> {
        let nonce_bytes = self.nonce.to_be_bytes();
        let ctr_bytes = self.ctr.to_be_bytes();

        let mut block = GenericArray::default();

        block[..8].copy_from_slice(&nonce_bytes);
        block[C::block_size()/2..C::block_size()/2+8].copy_from_slice(&ctr_bytes);

        self.cipher.encrypt_block(&mut block);

        self.ctr += 1;

        Some(block)
    }
}

fn AES128CTR(key: &[u8], nonce: u64, dst: &mut [u8], src: &[u8]) {
    let mut stream = CTRKeyStream::<Aes128>::new(key, nonce).unwrap();

    let mut dst_chunks: Vec<&mut [u8]> = dst.chunks_mut(Aes128::block_size()).collect();

    for (chunk, src_chunk) in src.chunks(Aes128::block_size()).enumerate() {
        let block = stream.next().unwrap();
        
        let res: Vec<u8> = block[..src_chunk.len()].iter()
            .zip(src_chunk)
            .map(|(&x1, &x2)| x1 ^ x2)
            .collect();

        dst_chunks[chunk].copy_from_slice(&res);
    }
}

fn main() {
    let mut rng = StdRng::from_os_rng();
    let nonce = rng.next_u64();

    let key = GenericArray::from([42u8; 16]);

    let src = "Hello".as_bytes();

    println!("{:?}", src);

    let mut dst = vec![0u8; src.len()];

    AES128CTR(&key, nonce, &mut dst, &src);

    println!("{:?}", dst);

    let mut dst2 = vec![0u8; dst.len()];

    AES128CTR(&key, nonce, &mut dst2, &dst);

    println!("{:?}", dst2);
}
