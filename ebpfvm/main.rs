use std::fs;
use std::env;
use byteorder::LittleEndian;
use byteorder::ByteOrder;
use std::io::Error;
use std::collections::HashMap;


#[derive(Debug)]
struct ebpf_inst {
    pub opcode: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

struct VMContext {
    pub program: Vec<u8>,
    pub helpers: HashMap<u32, Helper>,
}


type Helper = fn(u64, u64, u64, u64, u64) -> u64;

const STACK_SIZE :usize = 128;

impl VMContext {
    fn register_func(&mut self, key: u32,  func: Helper) -> Option<Helper> {
        self.helpers.insert(key, func)
    }

    fn exec_program(&self) -> Result<u64, Error> {
        let insts_len = self.program.len();
        let stack = vec![0; STACK_SIZE];
        let mut reg: [u64; 11] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, stack.as_ptr() as u64+ stack.len() as u64
        ];
        let mut mem = [0u8; 1024];
        mem[0] = 1;
        mem[1] = 2;
        mem[2] = 3;
        mem[3] = 4;
        mem[4] = 5;
        mem[5] = 6;
        mem[6] = 7;
        mem[7] = 8;
        mem[15] = 0x80;
        mem[16] = 1;
        mem[18] = 2;

        mem[22] = 2;
        mem[26] = 4;
        mem[30] = 8;
        mem[33] = 1;
        mem[37] = 2;
        reg[1] = mem.as_ptr() as u64;
        let mut inst_ptr :usize = 0;
        while inst_ptr * 8 < insts_len {
            let insn = ebpf_inst {opcode: self.program[inst_ptr*8],
                            dst: self.program[inst_ptr*8+1]&0xf,
                            src: self.program[inst_ptr*8+1]>>4,
                            off: LittleEndian::read_i16(&self.program[(inst_ptr*8+2)..]),
                            imm: LittleEndian::read_i32(&self.program[(inst_ptr*8+4)..]),
                            };
            let _dst = insn.dst as usize;
            let _src = insn.src as usize;
            inst_ptr += 1;
    
            match insn.opcode {
                /* ALU 64*/
                0x07 => { 
                    println!("inst = {:?}", insn);
                    reg[_dst] = reg[_dst].wrapping_add(insn.imm as u64);
                    },
                0x0f => reg[_dst] = reg[_dst].wrapping_add(reg[_src]),
                0x17 => reg[_dst] = reg[_dst].wrapping_sub(insn.imm as u64),
                0x1f => reg[_dst] = reg[_dst].wrapping_sub(reg[_src]),
                0x27 => reg[_dst] = reg[_dst].wrapping_mul(insn.imm as u64),
                0x2f => reg[_dst] = reg[_dst].wrapping_mul(reg[_src]),
                0x37 => reg[_dst] /= insn.imm as u64,
                0x3f => reg[_dst] /= reg[_src],
                0x47 => reg[_dst] |= insn.imm as u64,
                0x4f => reg[_dst] |= reg[_src],
                0x57 => reg[_dst] &= insn.imm as u64,
                0x5f => reg[_dst] &= reg[_src],
                0x67 => reg[_dst] <<= insn.imm as u64,
                0x6f => reg[_dst] <<= reg[_src],
                0x77 => reg[_dst] >>= insn.imm as u64,
                0x7f => reg[_dst] >>= reg[_src],
                0x87 => reg[_dst] = -(reg[_dst] as i64) as u64,
                0x97 => reg[_dst] %= insn.imm as u64,
                0x9f => reg[_dst] %= reg[_src],
                0xa7 => reg[_dst] ^= insn.imm as u64,
                0xaf => reg[_dst] ^= reg[_src],
                0xb7 => reg[_dst] = insn.imm as u64, 
                0xbf => reg[_dst] = reg[_src],
                0xc7 => reg[_dst] = (reg[_dst] as i64 >> insn.imm) as u64,
                0xcf => reg[_dst] = (reg[_dst] as i64 >> reg[_src]) as u64,
                
                /* ALU 32 */
                0x04 => reg[_dst] = (reg[_dst] + insn.imm as u64) & 0xffffffff,
                0x0c => reg[_dst] = (reg[_dst] + reg[_src]) & 0xffffffff,
                0x14 => reg[_dst] = (reg[_dst] - insn.imm as u64) & 0xffffffff,
                0x1c => reg[_dst] = (reg[_dst] - reg[_src]) & 0xffffffff,
                0x24 => reg[_dst] = (reg[_dst] * insn.imm as u64) & 0xffffffff,
                0x2c => reg[_dst] = (reg[_dst] * reg[_src]) & 0xffffffff,
                0x34 => reg[_dst] = (reg[_dst] / insn.imm as u64) & 0xffffffff,
                0x3c => reg[_dst] = (reg[_dst] / reg[_src]) & 0xffffffff,
                0x44 => reg[_dst] = (reg[_dst] | insn.imm as u64) & 0xffffffff,
                0x4c => reg[_dst] = (reg[_dst] | reg[_src]) & 0xffffffff,
                0x54 => reg[_dst] = (reg[_dst] & insn.imm as u64) & 0xffffffff,
                0x5c => reg[_dst] = (reg[_dst] & reg[_src]) & 0xffffffff,
                0x64 => reg[_dst] = (reg[_dst] << insn.imm as u64) & 0xffffffff,
                0x6c => reg[_dst] = (reg[_dst] << reg[_src]) & 0xffffffff,
                0x74 => reg[_dst] = (reg[_dst] >> insn.imm as u64) & 0xffffffff,
                0x7c => reg[_dst] = (reg[_dst] >> reg[_src]) & 0xffffffff,
                0x84 => reg[_dst] = (-(reg[_dst] as i64)) as u64 & 0xffffffff,
                0x94 => reg[_dst] = (reg[_dst] % insn.imm as u64) & 0xffffffff,
                0x9c => reg[_dst] = (reg[_dst] % reg[_src]) & 0xffffffff,
                0xa4 => reg[_dst] = (reg[_dst] ^ insn.imm as u64) & 0xffffffff,
                0xac => reg[_dst] = (reg[_dst] ^ reg[_src]) & 0xffffffff,
                0xb4 => reg[_dst] = insn.imm as u64 & 0xffffffff,
                0xbc => reg[_dst] = reg[_src] & 0xffffffff,
                0xc4 => reg[_dst] = (reg[_dst] as i32 >> insn.imm) as u64 & 0xffffffff,
                0xcc => reg[_dst] = (reg[_dst] as i32 >> reg[_src]) as u64 & 0xffffffff,

                /* branch */
                0x05 => inst_ptr += insn.off as usize,
                0x15 => if reg[_dst] == insn.imm as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x1d => if reg[_dst] == reg[_src] { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x25 => if reg[_dst] > insn.imm as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x2d => if reg[_dst] > reg[_src] { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x35 => if reg[_dst] >= insn.imm as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x3d => if reg[_dst] >= reg[_src] { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x45 => if reg[_dst] & insn.imm as u64 != 0 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x4d => if reg[_dst] & reg[_src] != 0 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x55 => if reg[_dst] != insn.imm as u64 { inst_ptr =  (inst_ptr as i64 + insn.off as i64) as usize;},
                0x5d => if reg[_dst] != reg[_src] { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x65 => if reg[_dst] as i64 > insn.imm as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x6d => if reg[_dst] as i64 > reg[_src] as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x75 => if reg[_dst] as i64 >= insn.imm as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x7d => if reg[_dst] as i64 >= reg[_src] as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xa5 => if reg[_dst] < insn.imm as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xad => if reg[_dst] < reg[_src] as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xb5 => if reg[_dst] <= insn.imm as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xbd => if reg[_dst] <= reg[_src] as u64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xc5 => if (reg[_dst] as i64) < insn.imm as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xcd => if (reg[_dst] as i64) < reg[_src] as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xd5 => if reg[_dst] as i64 <= insn.imm as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0xdd => if reg[_dst] as i64 <= reg[_src] as i64 { inst_ptr = (inst_ptr as i64 + insn.off as i64) as usize;},
                0x85 => if let Some(func) = self.helpers.get(&(insn.imm as u32)) {
                            reg[0] = func(reg[1],reg[2],reg[3],reg[4],reg[5]);
                        } else {
                            println!("no such function");
                        }
                0x95 => return Ok(reg[0]),
    
                /* memory */
                0x18 => {
                    let next_inst = ebpf_inst {opcode: self.program[inst_ptr*8],
                            dst: self.program[inst_ptr*8+1]&0xf,
                            src: self.program[inst_ptr*8+1]>>4,
                            off: LittleEndian::read_i16(&self.program[(inst_ptr*8+2)..]),
                            imm: LittleEndian::read_i32(&self.program[(inst_ptr*8+4)..]),
                            };
                    inst_ptr += 1;
                    reg[_dst] = insn.imm as u64 + (next_inst.imm as u64) << 32;
                },
                0x20 => reg[0] = unsafe {
                    let x = ((insn.imm as u32) as u64) as *const u32;
                    *x as u64
                },
                0x28 => reg[0] = unsafe {
                    let x = ((insn.imm as u32) as u64) as *const u16;
                    *x as u64
                },
                0x30 => reg[0] = unsafe {
                    let x = ((insn.imm as u32) as u64) as *const u8;
                    *x as u64
                },
                0x38 => reg[0] = unsafe {
                    let x = ((insn.imm as u32) as u64) as *const u64;
                    *x as u64
                },
                0x40 => reg[0] = unsafe {
                    let x = (reg[_src] + (insn.imm as u32) as u64) as *const u32;
                    *x as u64
                },
                0x48 => reg[0] = unsafe {
                    let x = (reg[_src] + (insn.imm as u32) as u64) as *const u16;
                    *x as u64
                },
                0x50 => reg[0] = unsafe {
                    let x = (reg[_src] + (insn.imm as u32) as u64) as *const u8;
                    *x as u64
                },
                0x58 => reg[0] = unsafe {
                    let x = (reg[_src] + (insn.imm as u32) as u64) as *const u64;
                    *x as u64
                },
                0x61 => reg[_dst] = unsafe {
                    let x = (reg[_src] + insn.off as u64) as *const u32;
                    *x as u64
                },
                0x69 => reg[_dst] = unsafe {
                    let x = (reg[_src] + insn.off as u64) as *const u16;
                    *x as u64
                },
                0x71 => reg[_dst] = unsafe {
                    let x = (reg[_src] + insn.off as u64) as *const u8;
                    *x as u64
                },
                0x79 => reg[_dst] = unsafe {
                    let x = (reg[_src] + insn.off as u64) as *const u64;
                    *x as u64
                },
                0x62 => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u32;
                    *x = insn.imm as u32;
                }, 
                0x6a => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u16;
                    *x = (insn.imm & 0xffff) as u16;
                },
                0x72 => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u8;
                    *x = (insn.imm & 0xff) as u8;
                },
                0x7a => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u64;
                    *x = insn.imm as u64;
                },
                0x63 => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u32;
                    *x = (reg[_src] & 0xffffffff) as u32;
                },
                0x6b => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u16;
                    *x = (reg[_src] & 0xffff) as u16;
                },
                0x73 => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u8;
                    *x = (reg[_src] & 0xff) as u8;
                },
                0x7b => unsafe {
                    let x = (reg[_dst]  + insn.off as u64) as *mut u64;
                    *x = reg[_src] as u64;
                },

                /* byte swap */ 
                0xd4 => {
                    reg[_dst] = match insn.imm {
                                    16 => (reg[_dst] as u16).to_le() as u64,
                                    32 => (reg[_dst] as u32).to_le() as u64,
                                    64 => reg[_dst].to_le(),
                                    _ => unreachable!()
                                };
                },
                0xdc => {
                    reg[_dst] = match insn.imm {
                                    16 => (reg[_dst] as u16).to_be() as u64,
                                    32 => (reg[_dst] as u32).to_be() as u64,
                                    64 => reg[_dst].to_be(),
                                    _ => unreachable!()
                                };
                },
                
                _ => {
                    println!("{:?} is not implemented", insn);
                    unimplemented!()
                }
            }
        }
        unreachable!();
    }
}

fn gather_bytes(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    (arg1 << 32) | (arg2 << 24) | (arg3 << 16) | (arg4 << 8) | arg5
}

fn memfrob(arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> u64 {
    for i in 0..arg2 {
        unsafe {
            let mut p = (arg1 +i) as *mut u8;
            *p ^= 0b101010;
        }
    }
    0
}


fn main() {
    let args: Vec<String> = env::args().collect();
    let mut vc = VMContext {
                program: fs::read(&args[1]).unwrap(),
                helpers: HashMap::new()
             };
    vc.register_func(0, gather_bytes);
    vc.register_func(1, memfrob);
    let result = vc.exec_program();
    println!("ebpf program result is {:x}", result.unwrap());
}
