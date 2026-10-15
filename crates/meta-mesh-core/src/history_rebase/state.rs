use super::*;

pub(super) fn walk(
    source: &AutoCommit,
    target: Option<&mut AutoCommit>,
) -> Result<(String, u64), String> {
    let mut hash = Sha256::new();
    hash.update(b"MESH-HISTORY/1/current-state\0");
    hash.update([1]);
    let copying = target.is_some();
    let mut walker = Walker {
        source,
        target,
        hash,
        nodes: 0,
    };
    walker.object(&ROOT, ObjType::Map, copying.then_some(ROOT), 0)?;
    Ok((URL_SAFE_NO_PAD.encode(walker.hash.finalize()), walker.nodes))
}

struct Walker<'a> {
    source: &'a AutoCommit,
    target: Option<&'a mut AutoCommit>,
    hash: Sha256,
    nodes: u64,
}
impl Walker<'_> {
    fn visit(&mut self, depth: usize) -> Result<(), String> {
        if depth > 128 || self.nodes == 1_048_576 {
            return Err("Native current-state preparation limit exceeded".into());
        }
        self.nodes += 1;
        Ok(())
    }
    fn length(&mut self, length: usize) {
        self.hash.update((length as u64).to_be_bytes());
    }
    fn bytes(&mut self, bytes: &[u8]) {
        self.length(bytes.len());
        self.hash.update(bytes);
    }
    fn object(
        &mut self,
        source: &ObjId,
        kind: ObjType,
        target: Option<ObjId>,
        depth: usize,
    ) -> Result<(), String> {
        self.visit(depth)?;
        match kind {
            ObjType::Map | ObjType::Table => {
                self.hash
                    .update([if kind == ObjType::Table { 4 } else { 1 }]);
                let mut keys = self.source.keys(source).collect::<Vec<_>>();
                keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
                self.length(keys.len());
                for key in keys {
                    self.bytes(key.as_bytes());
                    self.slot(source, Prop::Map(key), target.as_ref(), depth + 1)?;
                }
            }
            ObjType::List => {
                self.hash.update([2]);
                let count = self.source.length(source);
                self.length(count);
                for index in 0..count {
                    self.slot(source, Prop::Seq(index), target.as_ref(), depth + 1)?;
                }
            }
            ObjType::Text => {
                if !self
                    .source
                    .marks(source)
                    .map_err(|_| "Unable to inspect current text marks")?
                    .is_empty()
                {
                    return Err("Native rebase cannot yet preserve marked text".into());
                }
                let mut text = String::new();
                for span in self
                    .source
                    .spans(source)
                    .map_err(|_| "Unable to inspect current text blocks")?
                {
                    match span {
                        Span::Text { text: part, .. } => text.push_str(&part),
                        Span::Block(_) => {
                            return Err(
                                "Native rebase cannot yet preserve embedded text blocks".into()
                            );
                        }
                    }
                }
                self.hash.update([3]);
                self.bytes(text.as_bytes());
                if let (Some(target), Some(object)) = (self.target.as_mut(), target) {
                    target
                        .splice_text(object, 0, 0, &text)
                        .map_err(|_| "Unable to copy current text")?;
                }
            }
        }
        Ok(())
    }
    fn slot(
        &mut self,
        source: &ObjId,
        prop: Prop,
        target: Option<&ObjId>,
        depth: usize,
    ) -> Result<(), String> {
        let mut values = self
            .source
            .get_all(source, prop.clone())
            .map_err(|_| "Unable to inspect current value")?;
        if values.len() != 1 {
            return Err("Native rebase cannot yet preserve conflicting current values".into());
        }
        let (value, source_id) = values.pop().unwrap();
        match value {
            Value::Object(kind) => {
                let child = if let (Some(doc), Some(parent)) = (self.target.as_mut(), target) {
                    Some(
                        match &prop {
                            Prop::Map(key) => doc.put_object(parent, key, kind),
                            Prop::Seq(index) => doc.insert_object(parent, *index, kind),
                        }
                        .map_err(|_| "Unable to create current-state object")?,
                    )
                } else {
                    None
                };
                self.object(&source_id, kind, child, depth)?;
            }
            Value::Scalar(value) => {
                self.visit(depth)?;
                let scalar = copied_scalar(value.as_ref())?;
                self.scalar(&scalar);
                if let (Some(doc), Some(parent)) = (self.target.as_mut(), target) {
                    match &prop {
                        Prop::Map(key) => doc.put(parent, key, scalar),
                        Prop::Seq(index) => doc.insert(parent, *index, scalar),
                    }
                    .map_err(|_| "Unable to copy typed current value")?;
                }
            }
        }
        Ok(())
    }
    fn scalar(&mut self, scalar: &ScalarValue) {
        match scalar {
            ScalarValue::Null => self.hash.update([16]),
            ScalarValue::Boolean(value) => self.hash.update([if *value { 18 } else { 17 }]),
            ScalarValue::Str(value) => {
                self.hash.update([19]);
                self.bytes(value.as_bytes());
            }
            ScalarValue::Bytes(value) => {
                self.hash.update([20]);
                self.bytes(value);
            }
            ScalarValue::Int(value) => {
                self.hash.update([21]);
                self.hash.update(value.to_be_bytes());
            }
            ScalarValue::Uint(value) => {
                self.hash.update([22]);
                self.hash.update(value.to_be_bytes());
            }
            ScalarValue::F64(value) => {
                self.hash.update([23]);
                self.hash.update(value.to_bits().to_be_bytes());
            }
            ScalarValue::Counter(value) => {
                self.hash.update([24]);
                self.hash.update(i64::from(value).to_be_bytes());
            }
            ScalarValue::Timestamp(value) => {
                self.hash.update([25]);
                self.hash.update(value.to_be_bytes());
            }
            ScalarValue::Unknown { type_code, bytes } => {
                self.hash.update([26, *type_code]);
                self.bytes(bytes);
            }
        }
    }
}

fn copied_scalar(value: &ScalarValue) -> Result<ScalarValue, String> {
    Ok(match value {
        ScalarValue::Unknown { .. } => {
            return Err("Native rebase cannot yet preserve future scalar types".into());
        }
        ScalarValue::Counter(value) => ScalarValue::Counter(i64::from(value).into()),
        value => value.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_future_scalar_when_preparing_copy_then_reject_before_unsupported_automerge_save() {
        let value = ScalarValue::Unknown {
            type_code: 15,
            bytes: vec![9, 8, 7],
        };
        let original = value.clone();
        assert!(copied_scalar(&value).is_err());
        assert_eq!(value, original);
    }
}
