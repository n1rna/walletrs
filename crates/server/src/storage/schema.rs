use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub trait Storable: Serialize + for<'de> Deserialize<'de> + Clone {
    fn schema() -> Schema;
    fn validate(&self) -> Result<(), String>;
    fn get_indexable_fields(&self) -> HashMap<String, serde_json::Value>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub name: String,
    pub version: u32,
    pub description: String,
    pub fields: Vec<FieldSchema>,
    pub indexes: Vec<IndexSchema>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldSchema {
    pub name: String,
    pub field_type: FieldType,
    pub required: bool,
    pub description: String,
    pub validation: Option<FieldValidation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldType {
    String,
    Integer,
    Boolean,
    Float,
    DateTime,
    Json,
    Array(Box<FieldType>),
    Optional(Box<FieldType>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldValidation {
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    pub pattern: Option<String>,
    pub min_value: Option<f64>,
    pub max_value: Option<f64>,
    pub allowed_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSchema {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    pub description: String,
}

impl Schema {
    pub fn new(name: &str, version: u32, description: &str) -> Self {
        Self {
            name: name.to_string(),
            version,
            description: description.to_string(),
            fields: Vec::new(),
            indexes: Vec::new(),
        }
    }

    pub fn add_field(mut self, field: FieldSchema) -> Self {
        self.fields.push(field);
        self
    }

    pub fn add_index(mut self, index: IndexSchema) -> Self {
        self.indexes.push(index);
        self
    }
}

impl FieldSchema {
    pub fn new(name: &str, field_type: FieldType, required: bool, description: &str) -> Self {
        Self {
            name: name.to_string(),
            field_type,
            required,
            description: description.to_string(),
            validation: None,
        }
    }

    pub fn with_validation(mut self, validation: FieldValidation) -> Self {
        self.validation = Some(validation);
        self
    }
}

impl IndexSchema {
    pub fn new(name: &str, fields: Vec<&str>, unique: bool, description: &str) -> Self {
        Self {
            name: name.to_string(),
            fields: fields.into_iter().map(|s| s.to_string()).collect(),
            unique,
            description: description.to_string(),
        }
    }
}
