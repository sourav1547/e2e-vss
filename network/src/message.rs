use std::any::TypeId;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;

pub type Instance = Vec<usize>;

/// A protocol message. It is implicitly generic over all
/// ['static + Serializable + DeserializeOwned] types.
///
/// It is defined by the sending node [node], the id [id] (which comprises the
/// type of the content, round and instance, i.e., a vector of integers) and the content.
///
/// We explicitly erase the type of the message (instead of using generics) so that e.g., vectors
/// can handle message of different types within the network implementation.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Message<S> {
    sender: S,
    id: Id,
    type_id: u64,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
}

impl<S> Message<S>
    where
        S: Clone,
{
    /// Creates a new [Message].
    pub fn new<T: 'static + Serialize>(sender: &S, id: &Id, content: &T) -> Result<Self> {
        let content = bincode::serialize(&content)?;
        let type_id = content_type::<T>();
        Ok(Self { sender: sender.clone(), id: id.clone(), type_id, content })
    }

    #[inline]
    pub fn get_id(&self) -> &Id {
        &self.id
    }

    #[inline]
    pub fn get_sender(&self) -> &S {
        &self.sender
    }

    #[inline]
    pub fn get_content_type(&self) -> u64 {
        self.type_id
    }

    pub fn content_is_type<T: 'static>(&self) -> bool {
        self.type_id == content_type::<T>()
    }

    /// Extracts the [content] from the message.
    /// Returns an error if the type does not match.
    pub fn get_content<T>(&self) -> Result<T>
        where
            T: 'static + DeserializeOwned
    {
        ensure!(self.type_id == content_type::<T>(), "Types do not match!");
        let content = bincode::deserialize::<T>(&self.content)?;
        Ok(content)
    }
}

/// Returns the type id of given type [T].
pub fn content_type<T: 'static>() -> u64 {
    let type_id = TypeId::of::<T>();
    let mut hasher = IdentityHasher::new();
    type_id.hash(&mut hasher);
    hasher.finish()
}


/// This is like a [Message] but it can only be serialized. The result of this serialization can be
/// deserialized into a [Message].
#[derive(Debug, Serialize)]
pub struct SerializableMessage<'a, 'b, S> {
    sender: &'a S,
    id: &'b Id,
    type_id: u64,
    #[serde(with = "serde_bytes")]
    content: Vec<u8>,
}

impl<'a, 'b, S> SerializableMessage<'a, 'b, S> {
    /// Creates a new [SerializableMessage].
    pub fn new<T: 'static + Serialize>(sender: &'a S, id: &'b Id, content: &T) -> Result<Self> {
        let content = bincode::serialize(&content)?;
        let type_id = content_type::<T>();
        Ok(Self { sender, id, type_id, content })
    }
}

/// A message ID. It comprises the round and instance (which is a vector of integers).
#[derive(Debug, Hash, Eq, PartialEq, Serialize, Deserialize, Clone)]
pub struct Id {
    round: usize,
    instance: Instance
}

impl Id {
    #[inline]
    pub fn new(round: usize, instance: Instance) -> Self {
        Self { round, instance }
    }

    #[inline]
    pub fn get_round(&self) -> usize {
        self.round
    }

    #[inline]
    pub fn get_instance(&self) -> Instance {
        self.instance.clone()
    }

    #[inline]
    pub fn push(&mut self, value: usize) {
        self.instance.push(value);
    }

    #[inline]
    pub fn pop(&mut self) -> Option<usize> {
        self.instance.pop()
    }

    #[inline]
    pub fn last(&self) -> Option<&usize>{
        self.instance.last()
    }

}

impl Default for Id {
    #[inline]
    fn default() -> Self {
        Self::new(0, vec![])
    }
}


/// This is very hacky workaround. Essentially, we want to Serialize a TypeId. At the time of
/// writing, a TypeId is just a u64 internally but we can't access it directly. Therefore, we
/// create a hasher, that expects to exactly 64 bit (= 8xu8) and converts them to a u64 on [finish].
///
/// The more hacky version would be parsing the [Debug] string but that would be too hacky.
struct IdentityHasher {
    content: Vec<u8>,
}

impl IdentityHasher {

    #[inline]
    fn new() -> Self {
        Self { content: Vec::with_capacity(8) }
    }
}
impl Hasher for IdentityHasher {

    #[inline]
    fn finish(&self) -> u64 {
        // This unwrap will only panic if future Rust versions will change how TypeID (or hashing)
        // is defined.
        u64::from_ne_bytes(self.content.clone().try_into().unwrap())
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.content.extend(bytes);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_identity_hasher_u64() {
        let x = 42u64;
        let mut hasher = IdentityHasher::new();
        x.hash(&mut hasher);
        assert_eq!(x, hasher.finish())
    }

    #[test]
    fn test_identity_hasher_type() {
        // Hacky test for a hacky workaround
        let x = TypeId::of::<usize>();
        let y = format!("{:?}", x);
        // y = "TypeId { t: 8766594652559642870 }"
        let z = &y["TypeId { t: ".len()..y.len()-2];
        let mut hasher = IdentityHasher::new();
        x.hash(&mut hasher);
        assert_eq!(u64::from_str(z).unwrap(), hasher.finish())
    }
}
