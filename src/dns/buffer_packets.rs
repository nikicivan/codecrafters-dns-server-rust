#[derive(Debug)]
pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub position: u8,
}

impl BytePacketBuffer {
    pub fn new() -> Self {
        Self {
            buf: [0; 512],
            position: 0,
        }
    }
}
