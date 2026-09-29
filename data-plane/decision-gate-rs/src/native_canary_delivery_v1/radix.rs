//! Exact delivery-only SQL radix-16 membership and complete mutation delta.
//! Supplied before roots acquire currentness only from the independent signed
//! planner/executor/witness chain checked by completion.rs, never this function.
use super::wire::*;
use serde_json::{Value,json};
use sha2::{Digest,Sha256};
use std::collections::{BTreeMap,BTreeSet};

pub(crate) const TABLES:[&str;7]=["metadata_audit_outbox","policy_authority_bounded_aggregate_states","policy_authority_transition_audits",
    "policy_canary_delivery_heads","policy_canary_delivery_parts","policy_canary_delivery_slots","policy_canary_intake_batches"];
pub(crate) fn key_columns(table:&str)->Result<&'static [&'static str],String> {
    match table {
        "metadata_audit_outbox"|"policy_canary_delivery_heads"|"policy_canary_delivery_slots"=>Ok(&["id"]),
        "policy_authority_transition_audits"=>Ok(&["transition_digest"]),
        "policy_authority_bounded_aggregate_states"=>Ok(&["aggregate_id"]),
        "policy_canary_delivery_parts"=>Ok(&["slot_id","ordinal"]),
        "policy_canary_intake_batches"=>Ok(&["request_id"]),
        _=>Err("delivery proof names undeclared relation".into()),
    }
}
fn writable(operation:Operation,table:&str)->bool {
    ["metadata_audit_outbox","policy_authority_bounded_aggregate_states","policy_authority_transition_audits"].contains(&table)
        || operation!=Operation::Recover && (["policy_canary_delivery_heads","policy_canary_delivery_slots"].contains(&table)
            || operation==Operation::Prepare && table=="policy_canary_delivery_parts")
}
fn mutation_kind(operation:Operation,table:&str,kind:&str)->bool {
    match table {
        "metadata_audit_outbox"|"policy_authority_transition_audits"=>kind=="INSERT",
        "policy_authority_bounded_aggregate_states"=>kind=="UPDATE",
        "policy_canary_delivery_heads"=>operation==Operation::Prepare && ["INSERT","UPDATE"].contains(&kind) || operation==Operation::Claim && kind=="UPDATE",
        "policy_canary_delivery_slots"=>operation==Operation::Prepare && kind=="INSERT" || operation==Operation::Claim && kind=="UPDATE",
        "policy_canary_delivery_parts"=>operation==Operation::Prepare && kind=="INSERT",
        _=>false,
    }
}
/// Exact closed producer contract, independently reconstructed from source.
/// The source revision is admitted by the separately rooted full cold config;
/// callers cannot select dependencies, templates, grants or work ceilings.
pub(crate) fn handler_commitment(operation:Operation,source:&str)->Result<String,String>{
    let handler=format!("serverware_policy_authority_policy_canary_delivery_{}",operation.phase());
    let writes=TABLES.iter().copied().filter(|t|writable(operation,t)).collect::<Vec<_>>();
    let reads=TABLES.iter().copied().filter(|t|!writable(operation,t)).collect::<Vec<_>>();
    let framework_preconditions=["policy_authority_authorization_dependency_manifests","policy_authority_fence_heads","policy_authority_query_dependency_manifests"];
    let framework_writes=["policy_authority_authenticated_leaves","policy_authority_authenticated_root_revisions","policy_authority_authenticated_table_roots",
        "policy_authority_authenticated_tree_nodes","policy_authority_authorization_projections","policy_authority_consumed_envelopes",
        "policy_authority_execution_envelopes","policy_authority_planner_transactions","policy_authority_writer_capabilities","policy_authority_writer_receipts"];
    let framework_read_before_write=["policy_authority_authorization_projections","policy_authority_execution_envelopes","policy_authority_planner_transactions","policy_authority_writer_capabilities"];
    let mut all_reads=TABLES.to_vec();all_reads.extend(framework_preconditions);all_reads.extend(framework_writes);all_reads.sort();all_reads.dedup();
    let mut all_writes=writes.clone();all_writes.extend(framework_writes);all_writes.sort();all_writes.dedup();
    let mut templates=Vec::new();
    for table in &writes {for kind in ["INSERT","UPDATE"] {if mutation_kind(operation,table,kind){
        let mut template=json!({"schema":"serverware.policyAuthorityMutationTemplate/v1","operation":operation.label(),"table":table,"mutation":kind,
            "before":if kind=="INSERT"{"absent"}else{"present"},"after":"present","predicate":"exact-primary-key-and-full-row-cas-v1","cardinality":1});
        template["templateId"]=tree("serverware.policyAuthorityMutationTemplate/v1",&[&ascii(&template)?]).into();templates.push(template);
    }}}
    let transition=tree("serverware.policyAuthorityTransitionProgram/v1",&[&ascii(&json!({"operation":operation.label(),"handler":handler}))?]);
    let stem=operation.label().replace('.',"_").replace('-',"_");
    let suffix=hex::encode(Sha256::digest(operation.label().as_bytes()));let prefix="serverware_policy_authority_execute_";
    let tail=format!("_{}_v9",&suffix[..12]);
    let executor=format!("{prefix}{}{tail}",&stem[..stem.len().min(63-prefix.len()-tail.len())]);
    let value=json!({"sourceRevision":source,"operation":operation.label(),"handler":handler,
        "transitionProgramId":format!("serverware.policyAuthorityTransition/{}/{}/v1",operation.label(),&transition[7..23]),"planningMode":"typed-pure-transition",
        "businessReads":reads,"businessWrites":writes,"businessReadBeforeWrite":writes,"authorizationReads":[],
        "frameworkPreconditions":framework_preconditions,"frameworkWrites":framework_writes,"frameworkReadBeforeWrite":framework_read_before_write,
        "mutationTemplates":templates,"executorFunction":executor,"executorIdentityArguments":["text","text","text","text","text"],
        "reads":all_reads,"writes":all_writes,"selectors":{},"webauthn":"not-required","assertionRequired":false,"approverPolicyRequired":false,
        "proofPrimitives":["primary-key-row","aggregate-high-water"],"completeIndexQueryRoles":[],"globalAuditCapacity":true,
        "auditCapacityCounterSlotsReplaced":0,"auditCapacityAddsAggregateRoot":true,
        "maximumBusinessQueryRows":48,"maximumBusinessMutations":24,"maximumBusinessWorkUnits":8192,
        "maximumQueryRows":49,"maximumMutations":25,"maximumWorkUnits":8194,"externalEvidenceTypes":[],"opaqueValueKinds":[]});
    Ok(tree("serverware.policyAuthorityHandlerContract/v1",&[&ascii(&value)?]))
}
fn sql(value:&Value)->Result<Vec<u8>,String> {
    fn write(v:&Value,out:&mut Vec<u8>,depth:usize)->Result<(),String> {
        require(depth<=128,"delivery SQL JSON depth")?;
        match v {
            Value::Object(map)=>{out.push(b'{');let mut keys=map.keys().collect::<Vec<_>>();keys.sort();
                for (i,key) in keys.iter().enumerate(){if i>0{out.push(b',');}out.extend(serde_json::to_vec(*key).map_err(|_|"SQL JSON key")?);out.push(b':');write(&map[*key],out,depth+1)?;}out.push(b'}');},
            Value::Array(items)=>{out.push(b'[');for(i,item)in items.iter().enumerate(){if i>0{out.push(b',');}write(item,out,depth+1)?;}out.push(b']');},
            Value::Number(n)=>{require(n.is_i64()||n.is_u64(),"SQL proof refuses lossy numbers")?;out.extend(n.to_string().as_bytes());},
            _=>out.extend(serde_json::to_vec(v).map_err(|_|"SQL JSON scalar")?),
        }
        require(out.len()<=MAX_RESPONSE,"delivery SQL JSON byte bound")
    }
    let mut result=Vec::new();write(value,&mut result,0)?;Ok(result)
}
fn tree(domain:&str,frames:&[&[u8]])->String {
    let mut hash=Sha256::new();hash.update((domain.len() as u64).to_be_bytes());hash.update(domain.as_bytes());
    for frame in frames{hash.update((frame.len() as u64).to_be_bytes());hash.update(frame);}format!("sha256:{}",hex::encode(hash.finalize()))
}
fn node(depth:usize,children:&Value)->Result<String,String>{Ok(tree("serverware.policyAuthorityAuthenticatedNode/v1",&[depth.to_string().as_bytes(),&sql(children)?]))}
fn leaf(table:&str,path:&str,key:&Value,row:&Value,empty:&str)->Result<(Value,String),String>{
    if row.is_null(){return Ok((Value::Null,empty.into()));}
    let row_digest=tree("serverware.policyAuthorityAuthenticatedRow/v1",&[table.as_bytes(),&sql(row)?]);
    let leaf=tree("serverware.policyAuthorityAuthenticatedLeaf/v1",&[table.as_bytes(),format!("sha256:{path}").as_bytes(),&sql(key)?,row_digest.as_bytes()]);
    Ok((row_digest.into(),leaf))
}
fn roots(value:&Value,empty:&str)->Result<BTreeMap<String,Value>,String>{
    let mut result=BTreeMap::new();let mut previous="";
    for root in value.as_array().ok_or("delivery root vector")? {
        exact(root,&["table","rootRevision","rootDigest","leafCount"])?;let table=text(root,"table")?;
        require(table>previous && TABLES.contains(&table),"delivery root inventory")?;previous=table;
        let count=number(root,"leafCount")?;let revision=number(root,"rootRevision")?;
        require(crate::native_currentness_v1::digest(text(root,"rootDigest")?) && (count==0)==(root["rootDigest"]==empty)
            && (revision>0 || count==0),"delivery root count/revision")?;result.insert(table.into(),root.clone());
    }Ok(result)
}
fn nodes(value:&Value,depth:usize)->Result<u64,String>{
    require(depth<=128,"delivery proof structure depth")?;
    let mut count=1;
    match value {Value::Object(map)=>for(key,value)in map{count+=nodes(&Value::String(key.clone()),depth+1)?+nodes(value,depth+1)?;},
        Value::Array(items)=>for value in items{count+=nodes(value,depth+1)?;},_=>{sql(value)?;}}
    require(count<=1_000_000,"delivery proof node bound")?;Ok(count)
}
pub(crate) fn verify(operation:Operation,plan:&Value)->Result<(),String>{
    let transition=&plan["rootTransition"];
    exact(transition,&["schema","profile","businessBeforeRoots","authorizationBeforeRoots","businessAfterRoots","authorizationAfterRoots","metrics"])?;
    require(transition["schema"]=="serverware.policyAuthorityPrimaryRootTransition/v1"
        && transition["profile"]=="serverware.policyAuthorityPrimaryRootTransitionProfile/v2"
        && transition["authorizationBeforeRoots"]==json!([]) && transition["authorizationAfterRoots"]==json!([]),"delivery root profile/classes")?;
    let empty_leaf=tree("serverware.policyAuthorityAuthenticatedEmptyLeaf/v1",&[b"64"]);
    let mut empty=empty_leaf.clone();for depth in (0..64).rev(){empty=node(depth,&json!(vec![empty;16]))?;}
    let before=roots(&transition["businessBeforeRoots"],&empty)?;
    require(before.keys().map(String::as_str).eq(TABLES),"delivery complete source-owned root inventory")?;
    let selected=plan["selectedBusinessRows"].as_array().ok_or("delivery selected rows")?;
    let proofs=plan["queryMultiproofs"].as_array().ok_or("delivery proofs")?;
    let mutations=plan["mutationPlan"].as_array().ok_or("delivery mutations")?;
    require(selected.len()<=49 && selected.len()==proofs.len() && mutations.len()<=25,"delivery proof operation bounds")?;
    let contracts=TABLES.iter().map(|table|Ok(json!({"table":table,"keyColumns":key_columns(table)?,"writeAccess":writable(operation,table),"rootClass":"business"})))
        .collect::<Result<Vec<_>,String>>()?;
    let snapshot=json!({"contracts":contracts,"businessRoots":transition["businessBeforeRoots"],"authorizationRoots":[],"selected":selected,"proofs":proofs,"mutations":mutations});
    let input_bytes=ascii(&snapshot)?.len();require(input_bytes<=MAX_RESPONSE,"delivery proof snapshot bytes")?;
    let json_nodes=nodes(&snapshot,0)?;
    let mut rows=BTreeMap::new();let mut present=BTreeMap::<String,u64>::new();
    for row in selected {
        exact(row,&["table","key","keyDigest","present","row","contractSelector"])?;let table=text(row,"table")?;
        exact(&row["key"],key_columns(table)?)?;let is_present=row["present"].as_bool().ok_or("delivery selected presence")?;
        require((is_present && row["row"].is_object()) || (!is_present && row["row"].is_null()),"delivery selected row shape")?;
        require(row["contractSelector"].is_null()||row["contractSelector"].is_string(),"delivery selector shape")?;
        if is_present { for column in key_columns(table)? {require(row["key"][*column]==row["row"][*column],"delivery full-row key")?;}*present.entry(table.into()).or_default()+=1; }
        let digest=framed("serverware.policyAuthorityBusinessKey/v1",&[table.as_bytes(),&ascii(&row["key"])?]);
        require(row["keyDigest"]==digest && rows.insert((table.to_owned(),digest),row).is_none(),"delivery repeated/incorrect selected key")?;
    }
    for(table,count)in present{require(count<=number(&before[&table],"leafCount")?,"delivery membership exceeds count")?;}
    let mut vectors=BTreeMap::<(String,usize,String),Value>::new();let mut paths=BTreeMap::new();let mut unique_paths=BTreeSet::new();let mut hashes=66u64;
    for proof in proofs {
        exact(proof,&["schema","table","key","keyDigest","present","rowDigest","leafDigest","rootRevision","rootDigest","siblings","proofDigest"])?;
        let table=text(proof,"table")?;let address=(table.to_owned(),text(proof,"keyDigest")?.to_owned());
        let row=rows.get(&address).ok_or("delivery unselected proof")?;
        let root=before.get(table).ok_or("delivery unknown proof root")?;
        require(proof["schema"]=="serverware.policyAuthorityRadixMultiproof/v3" && proof["key"]==row["key"]
            && proof["present"]==row["present"] && proof["rootRevision"]==root["rootRevision"] && proof["rootDigest"]==root["rootDigest"],"delivery proof source join")?;
        let mut unsigned=proof.clone();unsigned.as_object_mut().ok_or("delivery proof object")?.remove("proofDigest");
        require(proof["proofDigest"]==framed("serverware.policyAuthorityRadixMultiproof/v3",&[&ascii(&unsigned)?]),"delivery proof digest")?;
        let key_digest=tree("serverware.policyAuthorityAuthenticatedKey/v1",&[table.as_bytes(),&sql(&row["key"])?]);let path=key_digest[7..].to_owned();
        require(paths.insert(address,path.clone()).is_none() && unique_paths.insert((table.to_owned(),path.clone())),"delivery repeated proof/path")?;
        let(row_digest,mut parent)=leaf(table,&path,&row["key"],&row["row"],&empty_leaf)?;
        require(proof["rowDigest"]==row_digest && proof["leafDigest"]==parent,"delivery authenticated leaf")?;
        let siblings=proof["siblings"].as_array().ok_or("delivery sibling vectors")?;require(siblings.len()==64,"delivery proof depth")?;
        hashes+=68+if row["present"]==true{2}else{0};
        for depth in (0..64).rev(){let level=&siblings[depth];exact(level,&["depth","pathPrefix","selectedNibble","childDigests"])?;
            let children=level["childDigests"].as_array().ok_or("delivery children")?;let nibble=&path[depth..depth+1];
            let index=usize::from_str_radix(nibble,16).map_err(|_|"delivery path nibble")?;
            require(number(level,"depth")?==depth as u64 && level["pathPrefix"]==path[..depth] && level["selectedNibble"]==nibble
                && children.len()==16 && children.iter().all(|v|v.as_str().is_some_and(crate::native_currentness_v1::digest)) && children[index]==parent,"delivery complete path")?;
            let address=(table.to_owned(),depth,path[..depth].to_owned());if let Some(old)=vectors.insert(address,level["childDigests"].clone()){
                require(old==level["childDigests"],"delivery inconsistent shared before prefix")?;}
            parent=node(depth,&level["childDigests"])?;
        }require(root["rootDigest"]==parent,"delivery reconstructed before root")?;
    }
    require(paths.len()==rows.len(),"delivery proof coverage")?;
    let mut seen=BTreeSet::new();let mut overlay=BTreeMap::new();let mut ancestors=BTreeSet::new();let mut deltas=BTreeMap::<String,(u64,i64)>::new();
    for change in mutations {
        exact(change,&["templateId","operation","table","key","keyDigest","expectedRow","row"])?;
        let table=text(change,"table")?;let address=(table.to_owned(),text(change,"keyDigest")?.to_owned());
        let old=rows.get(&address).ok_or("delivery unselected mutation")?;let operation_label=text(change,"operation")?;
        require(writable(operation,table) && seen.insert(address.clone()) && change["key"]==old["key"]
            && mutation_kind(operation,table,operation_label),"delivery mutation scope")?;
        let template=json!({"schema":"serverware.policyAuthorityMutationTemplate/v1","operation":operation.label(),"table":table,"mutation":operation_label,
            "before":if operation_label=="INSERT"{"absent"}else{"present"},"after":"present","predicate":"exact-primary-key-and-full-row-cas-v1","cardinality":1});
        require(change["templateId"]==tree("serverware.policyAuthorityMutationTemplate/v1",&[&ascii(&template)?]),"delivery exact mutation template")?;
        require(if operation_label=="INSERT"{old["present"]==false && change["expectedRow"].is_null()}else{old["present"]==true && change["expectedRow"]==old["row"]},"delivery original full-row CAS")?;
        require(change["row"].is_object(),"delivery after row")?;
        for column in key_columns(table)?{require(change["key"][*column]==change["row"][*column],"delivery after key")?;}
        let delta=deltas.entry(table.into()).or_default();delta.0+=1;if operation_label=="INSERT"{delta.1+=1;}
        let path=&paths[&address];let(_,leaf)=leaf(table,path,&change["key"],&change["row"],&empty_leaf)?;hashes+=2;
        overlay.insert((table.to_owned(),64,path.clone()),leaf);
        for depth in 0..64{ancestors.insert((std::cmp::Reverse(depth),table.to_owned(),path[..depth].to_owned()));}
    }
    for(std::cmp::Reverse(depth),table,prefix)in &ancestors {
        let mut children=vectors.get(&(table.clone(),*depth,prefix.clone())).ok_or("delivery missing mutation path")?.clone();
        let array=children.as_array_mut().ok_or("delivery child vector")?;
        for(index,child)in array.iter_mut().enumerate(){if let Some(value)=overlay.get(&(table.clone(),depth+1,format!("{prefix}{index:x}"))){*child=value.clone().into();}}
        overlay.insert((table.clone(),*depth,prefix.clone()),node(*depth,&children)?);hashes+=1;
    }
    let mut after=Vec::new();for(table,root)in &before{
        let mut next=root.clone();let(delta,count)=deltas.get(table).copied().unwrap_or_default();
        let revision=number(root,"rootRevision")?.checked_add(delta).filter(|v|*v<=i64::MAX as u64).ok_or("delivery root overflow")?;
        let leaves=number(root,"leafCount")?.checked_add_signed(count).filter(|v|*v<=i64::MAX as u64).ok_or("delivery count overflow")?;
        next["rootRevision"]=revision.into();next["leafCount"]=leaves.into();
        if let Some(digest)=overlay.get(&(table.clone(),0,String::new())){next["rootDigest"]=digest.clone().into();}after.push(next);
    }
    require(transition["businessAfterRoots"]==json!(after),"delivery complete after-root delta differs")?;
    let metrics=json!({"selectedRows":selected.len(),"mutations":mutations.len(),"proofVectors":selected.len()*64,
        "proofChildSlots":selected.len()*64*16,"recomputedAncestors":ancestors.len(),"hashWork":hashes,"inputBytes":input_bytes,"jsonNodes":json_nodes});
    require(transition["metrics"]==metrics,"delivery actual proof work metrics differ")
}
