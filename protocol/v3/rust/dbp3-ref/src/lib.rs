#![forbid(unsafe_code)]
use crc32fast::Hasher as Crc32;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use sha3::{digest::{ExtendableOutput, Update, XofReader}, Shake256};

pub const FRAME_SIZES:[usize;5]=[256,512,1024,2048,4096];
pub const HEADER_SIZE:usize=64;
pub const TRAILER_SIZE:usize=128;
pub const VERSION_FENCE:&[u8;4]=b"D3E4";
pub const REC_CRITICAL:u16=1;
mod generated_registry;
use generated_registry::{KNOWN_TYPES, RECORD_TYPES, SECURITY_SUITES, FEC_ALGORITHMS, DEVELOPMENT_HMAC_SUITE_ID};

type HmacSha256=Hmac<Sha256>;
fn u16le(b:&[u8],o:usize)->u16{u16::from_le_bytes([b[o],b[o+1]])}
fn u32le(b:&[u8],o:usize)->u32{u32::from_le_bytes(b[o..o+4].try_into().unwrap())}
fn u64le(b:&[u8],o:usize)->u64{u64::from_le_bytes(b[o..o+8].try_into().unwrap())}

#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct Header{pub flags:u32,pub frame_kind:u16,pub profile_id:u16,pub sequence:u64,pub session_epoch:u32,pub stream_id:u32,pub message_id:u32,pub source_time_us:u64,pub observed_time_us:u64,pub time_uncertainty_us:u32,pub body_used:u16,pub record_count:u16,pub path_id:u16,pub qos:u8,pub priority:u8}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct RecordInfo{pub type_id:u16,pub flags:u16,pub codec:u16,pub qos:u8,pub priority:u8,pub channel:u32,pub message_id:u64,pub fragment_index:u16,pub fragment_count:u16,pub payload_len:u32,pub deadline_ms:u32}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct DecodedFrame{pub frame_size:usize,pub header:Header,pub suite_id:u16,pub security_mode:u16,pub key_epoch:u32,pub fec:[u8;4],pub records:Vec<RecordInfo>}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct RegistrySnapshot{pub records:Vec<(u16,String)>,pub security_suites:Vec<(String,u16,String)>,pub fec_algorithms:Vec<(String,u8,String)>}
pub fn registry_snapshot()->RegistrySnapshot{RegistrySnapshot{records:RECORD_TYPES.iter().map(|(i,n)|(*i,(*n).to_string())).collect(),security_suites:SECURITY_SUITES.iter().map(|(n,i,s)|((*n).to_string(),*i,(*s).to_string())).collect(),fec_algorithms:FEC_ALGORITHMS.iter().map(|(n,i,s)|((*n).to_string(),*i,(*s).to_string())).collect()}}

fn shake32(domain:&[u8],data:&[u8])->[u8;32]{let mut h=Shake256::default();h.update(domain);h.update(data);let mut r=h.finalize_xof();let mut out=[0u8;32];r.read(&mut out);out}

pub fn parse_header(b:&[u8],frame_size:usize)->Result<Header,String>{
 if b.len()!=HEADER_SIZE||&b[0..4]!=b"DBP3"||b[4]!=3||b[5]!=4||u16le(b,6)!=64{return Err("abi".into())}
 let h=Header{flags:u32le(b,8),frame_kind:u16le(b,12),profile_id:u16le(b,14),sequence:u64le(b,16),session_epoch:u32le(b,24),stream_id:u32le(b,28),message_id:u32le(b,32),source_time_us:u64le(b,36),observed_time_us:u64le(b,44),time_uncertainty_us:u32le(b,52),body_used:u16le(b,56),record_count:u16le(b,58),path_id:u16le(b,60),qos:b[62],priority:b[63]};
 if h.frame_kind==0||h.profile_id==0||h.sequence==0||h.session_epoch==0||h.stream_id==0||h.message_id==0{return Err("one-origin".into())}
 let body_cap=frame_size.checked_sub(HEADER_SIZE+TRAILER_SIZE).ok_or("frame")?;if h.body_used as usize>body_cap{return Err("body-used".into())} Ok(h)
}
fn parse_records(data:&[u8],count:u16)->Result<Vec<RecordInfo>,String>{
 if count>128{return Err("record-limit".into())} let mut out=Vec::new();let mut off=0usize;
 for _ in 0..count{
  if off+32>data.len(){return Err("record-header".into())}
  let t=u16le(data,off);let f=u16le(data,off+2);let c=u16le(data,off+4);let q=data[off+6];let p=data[off+7];let ch=u32le(data,off+8);let mid=u64le(data,off+12);let fi=u16le(data,off+20);let fc=u16le(data,off+22);let n=u32le(data,off+24);let dl=u32le(data,off+28);off+=32;
  if t==0||mid==0||fc==0||fi>=fc{return Err("record-identity".into())} let end=off.checked_add(n as usize).ok_or("overflow")?;if end>data.len(){return Err("record-payload".into())} off=end;let pad=(4-(n as usize%4))%4;if off+pad>data.len()||data[off..off+pad].iter().any(|x|*x!=0){return Err("record-padding".into())}off+=pad;
  if f&REC_CRITICAL!=0&&!KNOWN_TYPES.contains(&t){return Err("unknown-critical".into())}
  out.push(RecordInfo{type_id:t,flags:f,codec:c,qos:q,priority:p,channel:ch,message_id:mid,fragment_index:fi,fragment_count:fc,payload_len:n,deadline_ms:dl});
 }
 if data[off..].iter().any(|x|*x!=0){return Err("trailing".into())} Ok(out)
}
pub fn decode_frame(raw:&[u8],dev_key:Option<&[u8]>)->Result<DecodedFrame,String>{
 let fs=raw.len();if !FRAME_SIZES.contains(&fs){return Err("frame-size".into())} let h=parse_header(&raw[..64],fs)?;if &raw[fs-4..]!=VERSION_FENCE{return Err("fence".into())}
 let expected=u32le(raw,fs-8);let mut crc=Crc32::new();crc.update(&raw[..fs-8]);if crc.finalize()!=expected{return Err("crc".into())}
 let toff=fs-TRAILER_SIZE;let body=&raw[HEADER_SIZE..toff];let tr=&raw[toff..];let logical=&body[..h.body_used as usize];if shake32(b"DBP3/PAYLOAD/v2",logical)!=tr[0..32]{return Err("payload-commitment".into())}
 if tr[92..96].iter().any(|x|*x!=0){return Err("reserved".into())} let suite=u16le(tr,80);let mode=u16le(tr,82);let key_epoch=u32le(tr,84);if key_epoch==0{return Err("key-epoch".into())}let fec=[tr[88],tr[89],tr[90],tr[91]];
 if !FEC_ALGORITHMS.iter().any(|(_,i,_)|*i==fec[0]){return Err("fec-scheme".into())}if fec[0]==0&&(fec[1]!=0||fec[2]!=0||fec[3]!=0){return Err("fec-tuple".into())}if fec[0]!=0&&(fec[1]==0||fec[2]<fec[1]||fec[3]>=fec[2]){return Err("fec-tuple".into())}
 if mode>1{return Err("security-mode".into())}
 if mode!=0{
  if h.flags&1==0{return Err("security-without-protected".into())}let key=dev_key.ok_or("security-key-unavailable")?;if suite!=DEVELOPMENT_HMAC_SUITE_ID{return Err("suite".into())}
  let mut msg=Vec::new();msg.extend_from_slice(b"DBP3/DEV-HMAC/v2");msg.extend_from_slice(&key_epoch.to_le_bytes());msg.extend_from_slice(&raw[..HEADER_SIZE]);msg.extend_from_slice(&tr[..96]);msg.extend_from_slice(body);
  let mut mac=HmacSha256::new_from_slice(key).map_err(|_|"hmac-key")?;mac.update(&msg);let tag=mac.finalize().into_bytes();if tag[..24]!=tr[96..120]{return Err("authentication".into())}
 }else{if suite!=0{return Err("suite-without-security".into())}if tr[96..120].iter().any(|x|*x!=0){return Err("tag-without-security".into())}if h.flags&1!=0{return Err("protected-without-security".into())}}
 let records=parse_records(logical,h.record_count)?;Ok(DecodedFrame{frame_size:fs,header:h,suite_id:suite,security_mode:mode,key_epoch,fec,records})
}


pub const MAX_ADMISSION_SCALAR:u64=(1u64<<31)-1;
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct AdmissionEstimate{pub estimated_heap_bytes:u64,pub estimated_cpu_tokens:u64,pub minimum_working_set_bytes:u64,pub cost_model_version:String}
fn checked_mul(a:u64,b:u64)->Result<u64,String>{if a>MAX_ADMISSION_SCALAR||b>MAX_ADMISSION_SCALAR{return Err("admission-scalar".into())}let v=a.checked_mul(b).ok_or("admission-overflow")?;if v>(1u64<<62){return Err("admission-overflow".into())}Ok(v)}
pub fn estimate_rust_runtime_cost(v:[u64;11])->Result<AdmissionEstimate,String>{
 let [frame,max_records,sessions,inflight,fec_k,fec_n,fec_groups,fanout,merge_page,merge_items,mailbox]=v;
 if !FRAME_SIZES.contains(&(frame as usize))||max_records<1||sessions<1{return Err("admission-request".into())}
 if v.iter().any(|x|*x>MAX_ADMISSION_SCALAR){return Err("admission-range".into())}
 if (fec_k==0)!=(fec_n==0)||fec_k>fec_n||fec_n>255{return Err("fec-request".into())}
 let base=128u64*1024;let min_ws=512u64*1024;
 let mut logical=base;
 for x in [checked_mul(sessions,frame*4)?,checked_mul(inflight,frame+256)?,checked_mul(checked_mul(max_records,sessions)?,192)?,checked_mul(if fec_n==0{1}else{fec_n},frame*3)?,merge_page.min(8*1024*1024),checked_mul(fanout,512)?,checked_mul(mailbox,256)?,checked_mul(fec_groups,1024)?,checked_mul(merge_items,64)?]{logical=logical.checked_add(x).ok_or("admission-overflow")?;}
 let heap=((logical.checked_mul(1400).ok_or("admission-overflow")?+999)/1000).max(min_ws);
 let mut cpu=0u64;
 for x in [checked_mul(sessions,600)?,checked_mul(inflight,30)?,checked_mul(checked_mul(max_records,sessions)?,25)?,checked_mul(checked_mul(if fec_n==0{1}else{fec_n},fec_k.max(1))?,45)?,checked_mul(fanout,20)?,checked_mul(fec_groups,35)?,checked_mul(merge_items,2)?]{cpu=cpu.checked_add(x).ok_or("admission-overflow")?;}
 Ok(AdmissionEstimate{estimated_heap_bytes:heap,estimated_cpu_tokens:cpu,minimum_working_set_bytes:min_ws,cost_model_version:"dbp3-runtime-cost/v2".to_string()})
}


#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct PlatformLimits{pub pointer_bits:u8,pub allocator_ceiling_bytes:u64,pub contiguous_allocation_ceiling_bytes:u64}
#[derive(Debug,Clone,PartialEq,Eq,Serialize)]
pub struct PlatformAdmission{pub required_contiguous_bytes:u64}
pub fn require_platform_admission(v:[u64;11],estimate:&AdmissionEstimate,platform:&PlatformLimits)->Result<PlatformAdmission,String>{
 if ![16u8,32,64].contains(&platform.pointer_bits){return Err("pointer-bits".into())}
 let addressable=if platform.pointer_bits==64{u64::MAX}else{(1u64<<platform.pointer_bits)-1};
 if platform.allocator_ceiling_bytes==0||platform.allocator_ceiling_bytes>addressable{return Err("allocator-width".into())}
 if platform.contiguous_allocation_ceiling_bytes==0||platform.contiguous_allocation_ceiling_bytes>platform.allocator_ceiling_bytes{return Err("contiguous-ceiling".into())}
 if estimate.estimated_heap_bytes>platform.allocator_ceiling_bytes||estimate.minimum_working_set_bytes>platform.allocator_ceiling_bytes{return Err("allocator-admission".into())}
 let frame=v[0];let fec_n=v[5].max(1);let merge=v[8].min(8*1024*1024);
 let required=frame.checked_mul(3).ok_or("platform-overflow")?.max(merge).max(frame.checked_mul(fec_n).ok_or("platform-overflow")?);
 if required>platform.contiguous_allocation_ceiling_bytes||required>addressable{return Err("contiguous-admission".into())}
 Ok(PlatformAdmission{required_contiguous_bytes:required})
}

#[cfg(test)]
mod tests{
 use super::*;
 #[test] fn rejects_short(){assert!(decode_frame(&[0u8;64],None).is_err());}
 #[test] fn frame_family_is_fixed(){assert_eq!(FRAME_SIZES,[256,512,1024,2048,4096]);}
 #[test] fn rust_cost_model_is_bounded(){let e=estimate_rust_runtime_cost([4096,64,8,64,8,12,16,32,1048576,256,128]).unwrap();assert!(e.estimated_heap_bytes>=e.minimum_working_set_bytes);}
 #[test] fn platform_width_guard_is_explicit(){let v=[4096,64,8,64,8,12,16,32,1048576,256,128];let e=estimate_rust_runtime_cost(v).unwrap();let p=PlatformLimits{pointer_bits:32,allocator_ceiling_bytes:512*1024*1024,contiguous_allocation_ceiling_bytes:8*1024*1024};assert!(require_platform_admission(v,&e,&p).is_ok());let tiny=PlatformLimits{pointer_bits:32,allocator_ceiling_bytes:256*1024,contiguous_allocation_ceiling_bytes:64*1024};assert!(require_platform_admission(v,&e,&tiny).is_err());}
}
