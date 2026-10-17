//! Recompute the closed native PREPARE SQL radix-16 membership and complete
//! mutation delta. Currentness additionally requires the durable effect hold.
use super::*;
#[path="relations.rs"] mod relations;
pub(super) use relations::{handler_commitment,guard_commitment,population_tables};
use relations::{tables,key_columns,writable,template,tree,AUTHORIZATION};
use std::collections::{BTreeMap,BTreeSet};
fn sql(v:&Value)->Result<Vec<u8>,ShadowError>{
    fn write(v:&Value,out:&mut Vec<u8>,depth:usize)->Result<(),ShadowError>{
        require(depth<=128)?;
        match v{
            Value::Object(map)=>{out.push(b'{');let mut keys=map.keys().collect::<Vec<_>>();keys.sort();
                for(i,k)in keys.iter().enumerate(){if i>0{out.push(b',');}out.extend(serde_json::to_vec(*k).map_err(fail)?);out.push(b':');write(&map[*k],out,depth+1)?;}out.push(b'}');},
            Value::Array(items)=>{out.push(b'[');for(i,item)in items.iter().enumerate(){if i>0{out.push(b',');}write(item,out,depth+1)?;}out.push(b']');},
            Value::Number(n)=>{require(n.is_i64()||n.is_u64())?;out.extend(n.to_string().as_bytes());},
            _=>out.extend(serde_json::to_vec(v).map_err(fail)?),
        }require(out.len()<=MAX_REQUEST)
    }
    let mut out=Vec::new();write(v,&mut out,0)?;Ok(out)
}
fn node(depth:usize,children:&Value)->Result<Sha256Digest,ShadowError>{Ok(tree("catchplate.policyAuthorityAuthenticatedNode/v1",&[depth.to_string().as_bytes(),&sql(children)?]))}
fn leaf(table:&str,path:&str,key:&Value,row:&Value,empty:&Sha256Digest)->Result<(Value,Sha256Digest),ShadowError>{
    if row.is_null(){return Ok((Value::Null,empty.clone()));}
    let row_digest=tree("catchplate.policyAuthorityAuthenticatedRow/v1",&[table.as_bytes(),&sql(row)?]);
    let leaf=tree("catchplate.policyAuthorityAuthenticatedLeaf/v1",&[table.as_bytes(),format!("sha256:{path}").as_bytes(),&sql(key)?,row_digest.as_str().as_bytes()]);
    Ok((serde_json::to_value(row_digest).map_err(fail)?,leaf))
}
fn roots(v:&Value,empty:&Sha256Digest,auth:bool)->Result<BTreeMap<String,Value>,ShadowError>{
    let mut out=BTreeMap::new();let mut previous="";let source=tables();
    for root in v.as_array().ok_or(ShadowError::BindingDrift)?{
        exact(root,&["table","rootRevision","rootDigest","leafCount"])?;let table=text(root,"table")?;
        require(table>previous && source.contains(&table) && AUTHORIZATION.contains(&table)==auth)?;previous=table;
        let count=number(root,"leafCount")?;let revision=number(root,"rootRevision")?;
        require((count==0)==(digest(root,"rootDigest")?==*empty) && (revision>0||count==0))?;
        out.insert(table.to_owned(),root.clone());
    }
    require(out.keys().map(String::as_str).eq(source.into_iter().filter(|t|AUTHORIZATION.contains(t)==auth)))?;Ok(out)
}
fn nodes(v:&Value,depth:usize)->Result<u64,ShadowError>{
    require(depth<=128)?;let mut n=1;
    match v{Value::Object(m)=>for(k,v)in m{n+=nodes(&Value::String(k.clone()),depth+1)?+nodes(v,depth+1)?;},
        Value::Array(a)=>for v in a{n+=nodes(v,depth+1)?;},_=>{sql(v)?;}}
    require(n<=1_000_000)?;Ok(n)
}
pub(super) fn verify(plan:&Value)->Result<(),ShadowError>{
    let transition=&plan["rootTransition"];
    exact(transition,&["schema","profile","businessBeforeRoots","authorizationBeforeRoots","businessAfterRoots","authorizationAfterRoots","metrics"])?;
    require(transition["schema"]=="catchplate.policyAuthorityPrimaryRootTransition/v1"
        && transition["profile"]=="catchplate.policyAuthorityPrimaryRootTransitionProfile/v2"
        && transition["authorizationAfterRoots"]==transition["authorizationBeforeRoots"])?;
    let empty_leaf=tree("catchplate.policyAuthorityAuthenticatedEmptyLeaf/v1",&[b"64"]);
    let mut empty=empty_leaf.clone();for depth in (0..64).rev(){empty=node(depth,&json!(vec![empty;16]))?;}
    let business=roots(&transition["businessBeforeRoots"],&empty,false)?;
    let auth=roots(&transition["authorizationBeforeRoots"],&empty,true)?;
    let mut before=business.clone();before.extend(auth);
    let selected=plan["selectedBusinessRows"].as_array().ok_or(ShadowError::BindingDrift)?;
    let proofs=plan["queryMultiproofs"].as_array().ok_or(ShadowError::BindingDrift)?;
    let mutations=plan["mutationPlan"].as_array().ok_or(ShadowError::BindingDrift)?;
    require(selected.len()<=257 && selected.len()==proofs.len() && mutations.len()<=17)?;
    let contracts=tables().iter().map(|t|Ok(json!({"table":t,"keyColumns":key_columns(t)?,"writeAccess":writable(t),
        "rootClass":if AUTHORIZATION.contains(t){"authorization"}else{"business"}}))).collect::<Result<Vec<_>,ShadowError>>()?;
    let snapshot=json!({"contracts":contracts,"businessRoots":transition["businessBeforeRoots"],"authorizationRoots":transition["authorizationBeforeRoots"],
        "selected":selected,"proofs":proofs,"mutations":mutations});
    let bytes=canonical_json_bytes(&snapshot)?.len();require(bytes<=MAX_REQUEST)?;let node_count=nodes(&snapshot,0)?;
    let mut rows=BTreeMap::new();let mut counts=BTreeMap::<String,u64>::new();
    for row in selected{
        exact(row,&["table","key","keyDigest","present","row","contractSelector"])?;let table=text(row,"table")?;
        exact(&row["key"],key_columns(table)?)?;let present=row["present"].as_bool().ok_or(ShadowError::BindingDrift)?;
        require(present && row["row"].is_object() || !present && row["row"].is_null())?;
        require(row["contractSelector"].is_null()||row["contractSelector"].is_string())?;
        if present{for k in key_columns(table)?{require(row["key"][*k]==row["row"][*k])?;}*counts.entry(table.into()).or_default()+=1;}
        let key_digest=framed("catchplate.policyAuthorityBusinessKey/v1",&[table.as_bytes(),&canonical_json_bytes(&row["key"])?]);
        require(digest(row,"keyDigest")?==key_digest && rows.insert((table.to_owned(),key_digest),row).is_none())?;
    }
    for(table,count)in counts{require(count<=number(before.get(&table).ok_or(ShadowError::BindingDrift)?,"leafCount")?)?;}
    let mut vectors=BTreeMap::<(String,usize,String),Value>::new();let mut paths=BTreeMap::new();let mut unique=BTreeSet::new();let mut hashes=66u64;
    for proof in proofs{
        exact(proof,&["schema","table","key","keyDigest","present","rowDigest","leafDigest","rootRevision","rootDigest","siblings","proofDigest"])?;
        let table=text(proof,"table")?;let address=(table.to_owned(),digest(proof,"keyDigest")?);
        let row=rows.get(&address).ok_or(ShadowError::BindingDrift)?;let root=before.get(table).ok_or(ShadowError::BindingDrift)?;
        require(proof["schema"]=="catchplate.policyAuthorityRadixMultiproof/v3" && proof["key"]==row["key"]
            && proof["present"]==row["present"] && proof["rootRevision"]==root["rootRevision"] && proof["rootDigest"]==root["rootDigest"])?;
        let mut unsigned=proof.clone();unsigned.as_object_mut().ok_or(ShadowError::BindingDrift)?.remove("proofDigest");
        require(proof["proofDigest"]==frame("catchplate.policyAuthorityRadixMultiproof/v3",&unsigned)?)?;
        let key=tree("catchplate.policyAuthorityAuthenticatedKey/v1",&[table.as_bytes(),&sql(&row["key"])?]);let path=key.as_str()[7..].to_owned();
        require(paths.insert(address,path.clone()).is_none() && unique.insert((table.to_owned(),path.clone())))?;
        let(row_digest,mut parent)=leaf(table,&path,&row["key"],&row["row"],&empty_leaf)?;
        require(proof["rowDigest"]==row_digest && digest(proof,"leafDigest")?==parent)?;
        let siblings=proof["siblings"].as_array().ok_or(ShadowError::BindingDrift)?;require(siblings.len()==64)?;
        hashes+=68+if row["present"]==true{2}else{0};
        for depth in (0..64).rev(){
            let level=&siblings[depth];exact(level,&["depth","pathPrefix","selectedNibble","childDigests"])?;
            let children=level["childDigests"].as_array().ok_or(ShadowError::BindingDrift)?;
            let nibble=&path[depth..depth+1];let index=usize::from_str_radix(nibble,16).map_err(fail)?;
            require(number(level,"depth")?==depth as u64 && level["pathPrefix"]==path[..depth] && level["selectedNibble"]==nibble
                && children.len()==16 && children.iter().all(|v|v.as_str().is_some_and(|s|Sha256Digest::parse(s.to_owned()).is_ok()))
                && children[index]==serde_json::to_value(&parent).map_err(fail)?)?;
            if let Some(old)=vectors.insert((table.to_owned(),depth,path[..depth].to_owned()),level["childDigests"].clone()){require(old==level["childDigests"])?;}
            parent=node(depth,&level["childDigests"])?;
        }require(digest(root,"rootDigest")?==parent)?;
    }require(paths.len()==rows.len())?;
    let mut changed=BTreeSet::new();let mut overlay=BTreeMap::new();let mut ancestors=BTreeSet::new();let mut deltas=BTreeMap::<String,(u64,u64)>::new();
    for change in mutations{
        exact(change,&["templateId","operation","table","key","keyDigest","expectedRow","row"])?;
        let table=text(change,"table")?;let address=(table.to_owned(),digest(change,"keyDigest")?);
        let old=rows.get(&address).ok_or(ShadowError::BindingDrift)?;let kind=text(change,"operation")?;
        require(writable(table) && changed.insert(address.clone()) && change["key"]==old["key"] && change["templateId"]==template(table,kind)?["templateId"])?;
        require(if kind=="INSERT"{old["present"]==false && change["expectedRow"].is_null()}else{old["present"]==true && change["expectedRow"]==old["row"]})?;
        require(change["row"].is_object())?;for k in key_columns(table)?{require(change["key"][*k]==change["row"][*k])?;}
        let delta=deltas.entry(table.into()).or_default();delta.0+=1;if kind=="INSERT"{delta.1+=1;}
        let path=&paths[&address];let(_,leaf)=leaf(table,path,&change["key"],&change["row"],&empty_leaf)?;hashes+=2;
        overlay.insert((table.to_owned(),64,path.clone()),leaf);for depth in 0..64{ancestors.insert((std::cmp::Reverse(depth),table.to_owned(),path[..depth].to_owned()));}
    }
    for(std::cmp::Reverse(depth),table,prefix)in &ancestors{
        let mut children=vectors.get(&(table.clone(),*depth,prefix.clone())).ok_or(ShadowError::BindingDrift)?.clone();
        for(index,child)in children.as_array_mut().ok_or(ShadowError::BindingDrift)?.iter_mut().enumerate(){
            if let Some(v)=overlay.get(&(table.clone(),depth+1,format!("{prefix}{index:x}"))){*child=serde_json::to_value(v).map_err(fail)?;}}
        overlay.insert((table.clone(),*depth,prefix.clone()),node(*depth,&children)?);hashes+=1;
    }
    let mut after=Vec::new();for(table,root)in business{
        let mut next=root.clone();let(changes,inserts)=deltas.get(&table).copied().unwrap_or_default();
        next["rootRevision"]=number(&root,"rootRevision")?.checked_add(changes).filter(|n|*n<=i64::MAX as u64).ok_or(ShadowError::CounterOverflow)?.into();
        next["leafCount"]=number(&root,"leafCount")?.checked_add(inserts).filter(|n|*n<=i64::MAX as u64).ok_or(ShadowError::CounterOverflow)?.into();
        if let Some(v)=overlay.get(&(table,0,String::new())){next["rootDigest"]=serde_json::to_value(v).map_err(fail)?;}after.push(next);
    }
    require(transition["businessAfterRoots"]==json!(after) && transition["metrics"]==json!({"selectedRows":selected.len(),"mutations":mutations.len(),
        "proofVectors":selected.len()*64,"proofChildSlots":selected.len()*64*16,"recomputedAncestors":ancestors.len(),"hashWork":hashes,"inputBytes":bytes,"jsonNodes":node_count}))?;
    let mut sources=Vec::new();let mut coverage=BTreeSet::new();
    for row in selected{let table=text(row,"table")?;if AUTHORIZATION.contains(&table){
        coverage.insert(table);sources.push(json!({"table":table,"selector":row["key"],"present":row["present"],"row":row["row"],
            "rowDigest":framed("catchplate.policyAuthorityAuthorizationRow/v1",&[table.as_bytes(),&canonical_json_bytes(&row["key"])?,
                if row["present"]==true{b"present"}else{b"absent"},&canonical_json_bytes(&row["row"])?])}));}}
    require(coverage.iter().copied().eq(AUTHORIZATION.iter().copied()) && sources.len()<=64)?;
    let mut keyed=sources.into_iter().map(|v|Ok(((text(&v,"table")?.to_owned(),canonical_json_bytes(&v["selector"])?),v))).collect::<Result<Vec<_>,ShadowError>>()?;
    keyed.sort_by(|a,b|a.0.cmp(&b.0));let sources=keyed.into_iter().map(|(_,v)|v).collect::<Vec<_>>();
    let projection=&plan["authorizationProjection"];
    require(projection["authorizationReads"]==json!(AUTHORIZATION) && projection["sourceRows"]==json!(sources)
        && projection["sourceHighWaterDigest"]==frame("catchplate.policyAuthorityAuthorizationRootSet/v1",&transition["authorizationBeforeRoots"])?)
}
