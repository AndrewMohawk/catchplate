//! Exact sealed, credential-free source inputs. Metadata originals are retained
//! with the durable claim; the HTTP template goes only to the private ledger.
use super::*;
use std::{fs::File,os::unix::fs::FileExt};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD,Engine as _};
const MAX_METADATA_OBJECT:usize=64*1024;
pub(crate) struct Inputs { files:Vec<File>, bytes:Vec<Vec<u8>>, retained:Vec<u8> }
impl Inputs {
    pub(crate) fn admit(config:&Config,request:&VerifiedRequest,files:Vec<File>)->Result<Self,V2RuntimeError> {
        request.check(config)?;
        let descriptors=request.original().request.exact_object_descriptors();
        let validated=super::super::validate_exact_object_files(&descriptors,files,None)?;
        let mut bytes=Vec::new();
        for (index,descriptor) in descriptors.iter().enumerate() {
            let maximum=if request.phase()=="STAGE"&&index==1 {wire::MAX_INPUT as usize} else {MAX_METADATA_OBJECT};
            if descriptor.byte_length>maximum as u64 {return Err(fail("staging exact input exceeds purpose bound"));}
            request.check(config)?;
            let object=validated.get(index as u16).ok_or_else(||fail("staging exact input missing"))?;
            let mut raw=vec![0;descriptor.byte_length as usize];
            let mut offset=0;
            while offset<raw.len() {
                request.check(config)?;
                let end=(offset+64*1024).min(raw.len());
                let count=object.read_at(&mut raw[offset..end],offset as u64)?;
                if count==0 {return Err(fail("staging exact input ended early"));} offset+=count;
            }
            if native::sha256(&raw)!=descriptor.sha256 {return Err(fail("staging exact input changed"));}
            bytes.push(raw);
        }
        let count=if request.phase()=="STAGE" {1} else {bytes.len()};
        let originals:Vec<String>=bytes[..count].iter().map(|raw|URL_SAFE_NO_PAD.encode(raw)).collect();
        let retained=native::canonical(&originals).map_err(fail)?;
        if retained.len()>256*1024 {return Err(fail("staging metadata originals exceed retained bound"));}
        let result=Self {files:validated.into_files(),bytes,retained};request.check(config)?;Ok(result)
    }
    pub(crate) fn retained(&self)->&[u8] {&self.retained}
    pub(crate) fn bytes(&self,index:usize)->Result<&[u8],V2RuntimeError> {
        self.bytes.get(index).map(Vec::as_slice).ok_or_else(||fail("staging exact original absent"))
    }
    pub(crate) fn clone_file(&self,index:usize)->Result<File,V2RuntimeError> {
        self.files.get(index).ok_or_else(||fail("staging sealed descriptor absent"))?.try_clone()
            .map_err(|_|fail("retain staging original descriptor"))
    }
    pub(crate) fn check(&self,config:&Config,request:&VerifiedRequest)->Result<(),V2RuntimeError> {
        request.check(config)?;
        let descriptors=request.original().request.exact_object_descriptors();
        let files=self.files.iter().map(File::try_clone).collect::<Result<Vec<_>,_>>()
            .map_err(|_|fail("retain staging descriptor originals"))?;
        super::super::validate_exact_object_files(&descriptors,files,None)?;
        for (index,file) in self.files.iter().enumerate() {
            let expected=&self.bytes[index];let mut raw=vec![0;expected.len()];
            file.read_exact_at(&mut raw,0).map_err(|_|fail("read retained staging original"))?;
            if raw!=*expected {return Err(fail("staging original bytes differ"));}
        }
        request.check(config)
    }
}
pub(crate) fn retained_metadata(request:&wire::StagingRequest,original:&[u8])->Result<Vec<Vec<u8>>,V2RuntimeError> {
    if original.is_empty()||original.len()>256*1024 {return Err(fail("retained staging metadata bound"));}
    let values:Vec<String>=serde_json::from_slice(original).map_err(|_|fail("retained staging metadata shape"))?;
    if native::canonical(&values).map_err(fail)?!=original {return Err(fail("retained staging metadata is not canonical"));}
    let phase=native::phase(&request.evidence.statement.original).map_err(fail)?;
    let expected=if phase=="RESERVE" {3} else if phase=="AUTHORIZE" {2} else {1};
    let descriptors=request.evidence.statement.original.request.exact_object_descriptors();
    if values.len()!=expected {return Err(fail("retained staging metadata inventory differs"));}
    values.iter().enumerate().map(|(index,value)| {
        if value.len()>MAX_METADATA_OBJECT*4/3+2 {return Err(fail("retained staging metadata object exceeds bound"));}
        let raw=URL_SAFE_NO_PAD.decode(value).map_err(|_|fail("retained staging metadata encoding"))?;
        if raw.is_empty()||raw.len()>MAX_METADATA_OBJECT||URL_SAFE_NO_PAD.encode(&raw)!=*value
            ||raw.len() as u64!=descriptors[index].byte_length||native::sha256(&raw)!=descriptors[index].sha256 {
            return Err(fail("retained staging metadata differs from measured exact descriptor"));
        }
        Ok(raw)
    }).collect()
}
