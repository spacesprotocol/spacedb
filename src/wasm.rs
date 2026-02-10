#[cfg(feature = "wasm")]
mod wasm_api {
    use alloc::format;
    use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
    use js_sys::{Array, Uint8Array};

    use crate::{
        subtree::SubTree as NativeSubTree,
        Sha256Hasher,
    };
    use crate::subtree::ValueOrHash;

    #[wasm_bindgen]
    pub struct SubTree {
        inner: NativeSubTree<Sha256Hasher>,
    }

    #[wasm_bindgen]
    impl SubTree {
        /// Creates a new SubTree.
        /// If `data` is provided (as a Uint8Array), the subtree is initialized from it;
        /// if omitted, an empty subtree is created.
        #[wasm_bindgen(constructor)]
        pub fn new(data: Option<Uint8Array>) -> Result<SubTree, JsValue> {
            match data {
                Some(array) => {
                    let buf = array.to_vec();
                    NativeSubTree::from_slice(&buf)
                        .map(|inner| SubTree { inner })
                        .map_err(|err| JsValue::from_str(&format!("Deserialization error: {:?}", err)))
                }
                None => {
                    Ok(SubTree {
                        inner: NativeSubTree::empty(),
                    })
                }
            }
        }

        /// Serializes the SubTree to a Uint8Array.
        #[wasm_bindgen]
        pub fn to_bytes(&self) -> Result<Uint8Array, JsValue> {
            let bytes = self.inner.to_vec()
                .map_err(|err| JsValue::from_str(&format!("Serialization error: {:?}", err)))?;
            Ok(Uint8Array::from(&bytes[..]))
        }

        /// Returns the root hash as a Uint8Array.
        #[wasm_bindgen]
        pub fn compute_root(&self) -> Result<Uint8Array, JsValue> {
            self.inner
                .compute_root()
                .map(|hash| Uint8Array::from(&hash[..]))
                .map_err(|err| JsValue::from_str(&format!("Error retrieving root: {:?}", err)))
        }

        /// Returns true if the subtree is empty.
        #[wasm_bindgen]
        pub fn is_empty(&self) -> bool {
            self.inner.is_empty()
        }

        /// Returns true if the subtree contains the given key.
        #[wasm_bindgen]
        pub fn contains(&self, key: &[u8]) -> Result<bool, JsValue> {
            if key.len() != 32 {
                return Err(JsValue::from_str("Invalid key length; expected 32 bytes"));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            self.inner
                .contains(&key_arr)
                .map_err(|err| JsValue::from_str(&format!("Contains error: {:?}", err)))
        }

        /// Inserts a full value associated with the given key.
        #[wasm_bindgen]
        pub fn insert_value(&mut self, key: &[u8], value: &[u8]) -> Result<(), JsValue> {
            if key.len() != 32 {
                return Err(JsValue::from_str("Invalid key length; expected 32 bytes"));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            self.inner
                .insert(key_arr, ValueOrHash::Value(value.to_vec()))
                .map_err(|err| JsValue::from_str(&format!("Insert error: {:?}", err)))
        }

        /// Inserts a hash associated with the given key.
        #[wasm_bindgen]
        pub fn insert_hash(&mut self, key: &[u8], hash: &[u8]) -> Result<(), JsValue> {
            if key.len() != 32 {
                return Err(JsValue::from_str("Invalid key length; expected 32 bytes"));
            }
            if hash.len() != 32 {
                return Err(JsValue::from_str("Invalid hash length; expected 32 bytes"));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            let mut hash_arr = [0u8; 32];
            hash_arr.copy_from_slice(hash);
            self.inner
                .insert(key_arr, ValueOrHash::Hash(hash_arr))
                .map_err(|err| JsValue::from_str(&format!("Insert error: {:?}", err)))
        }

        /// Deletes the key from the subtree, consuming this subtree and returning a new one.
        #[wasm_bindgen]
        pub fn delete(self, key: &[u8]) -> Result<SubTree, JsValue> {
            if key.len() != 32 {
                return Err(JsValue::from_str("Invalid key length; expected 32 bytes"));
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(key);
            self.inner
                .delete(&key_arr)
                .map(|new_tree| SubTree { inner: new_tree })
                .map_err(|err| JsValue::from_str(&format!("Delete error: {:?}", err)))
        }

        /// Returns an array of [key, value] pairs.
        /// Each key and value is a Uint8Array.
        #[wasm_bindgen]
        pub fn entries(&self) -> Result<Array, JsValue> {
            let arr = Array::new();
            for (key, value) in self.inner.iter() {
                let key_arr = Uint8Array::from(&key[..]);
                let value_arr = Uint8Array::from(&value[..]);
                let pair = Array::of2(&key_arr.into(), &value_arr.into());
                arr.push(&pair.into());
            }
            Ok(arr)
        }
    }
}
