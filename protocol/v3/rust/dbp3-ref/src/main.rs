use std::{env,fs,process};
fn main(){
 let a:Vec<String>=env::args().collect();
 if a.len()==2 && a[1]=="--registry"{println!("{}",serde_json::to_string(&dbp3_ref::registry_snapshot()).unwrap());return}
 if a.len()==13 && a[1]=="--estimate"{let mut v=[0u64;11];for i in 0..11{v[i]=a[i+2].parse().unwrap_or_else(|_|{eprintln!("bad estimate argument");process::exit(2)})}match dbp3_ref::estimate_rust_runtime_cost(v){Ok(e)=>println!("{}",serde_json::to_string(&e).unwrap()),Err(e)=>{eprintln!("REJECT:{e}");process::exit(1)}}return}
 if a.len()<2{eprintln!("usage: dbp3-conformance FILE [DEVKEYHEX] | --registry | --estimate <11 fields>");process::exit(2)}
 let raw=match fs::read(&a[1]){Ok(x)=>x,Err(e)=>{eprintln!("{e}");process::exit(2)}};let key=a.get(2).and_then(|s|hex::decode(s).ok());
 match dbp3_ref::decode_frame(&raw,key.as_deref()){Ok(f)=>{println!("{}",serde_json::to_string(&f).unwrap())},Err(e)=>{eprintln!("REJECT:{e}");process::exit(1)}}
}
