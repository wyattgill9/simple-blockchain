use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};
use ed25519_dalek::{SigningKey, Signature, Signer, VerifyingKey, Verifier};
use std::convert::TryFrom;

#[derive(Debug, Clone)]
pub struct Wallet {
    pub owner: String,
    pub balance: u64,
    pub signing_key: Option<SigningKey>,
    pub verifying_key: VerifyingKey,
}

impl Wallet {
    pub fn new(owner: String, initial_balance: u64) -> Self {
        let secret_key: [u8; 32] = rand::random(); // Generate random bytes
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        Wallet {
            owner,
            balance: initial_balance,
            signing_key: Some(signing_key),
            verifying_key,
        }
    }

    pub fn receive_only(owner: String, initial_balance: u64, verifying_key: VerifyingKey) -> Self {
        Wallet {
            owner,
            balance: initial_balance,
            signing_key: None,
            verifying_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<Signature, String> {
        match &self.signing_key {
            Some(key) => Ok(key.sign(message)),
            None => Err("Cannot sign: this is a receive-only wallet".to_string()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    pub from_public_key: [u8; 32],
    pub to_public_key: [u8; 32],
    pub amount: u64,
    pub timestamp: u64,
    pub signature: Option<[u8; 64]>,
}

impl Transaction {
    pub fn new(from: &Wallet, to: &Wallet, amount: u64) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Transaction {
            from_public_key: from.public_key_bytes(),
            to_public_key: to.public_key_bytes(),
            amount,
            timestamp,
            signature: None,
        }
    }

    pub fn transaction_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.from_public_key);
        data.extend_from_slice(&self.to_public_key);
        data.extend_from_slice(&self.amount.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }

    pub fn sign(&mut self, wallet: &Wallet) -> Result<(), String> {
        let data = self.transaction_data();
        let signature = wallet.sign_message(&data)?;
        self.signature = Some(signature.to_bytes());
        Ok(())
    }

    pub fn verify_signature(&self) -> Result<bool, String> {
        let signature_bytes = match self.signature {
            Some(sig) => sig,
            None => return Err("Transaction is not signed".to_string()),
        };

        let verifying_key = match VerifyingKey::from_bytes(&self.from_public_key) {
            Ok(key) => key,
            Err(_) => return Err("Invalid public key".to_string()),
        };

        let signature = match Signature::try_from(&signature_bytes[..]) {
            Ok(sig) => sig,
            Err(_) => return Err("Invalid signature format".to_string()),
        };

        match verifying_key.verify(&self.transaction_data(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Block {
    pub index: i32,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub prev_hash: String,
    pub hash: String,
    pub nonce: u64,
}

pub struct Blockchain {
    pub chain: Vec<Block>,
    pub pending_transactions: Vec<Transaction>,
    pub wallets: Vec<Wallet>,
}

impl Blockchain {
    pub fn new() -> Self {
        let genesis = Block {
            index: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            transactions: Vec::new(),
            prev_hash: "0".to_string(),
            hash: "0".to_string(),
            nonce: 0,
        };

        Blockchain {
            chain: vec![genesis],
            pending_transactions: Vec::new(),
            wallets: Vec::new(),
        }
    }

    pub fn register_wallet(&mut self, wallet: Wallet) {
        self.wallets.push(wallet);
    }

    pub fn find_wallet_by_public_key(&self, public_key: &[u8; 32]) -> Option<&Wallet> {
        self.wallets.iter().find(|w| w.public_key_bytes() == *public_key)
    }

    pub fn get_wallet_balance(&self, public_key: &[u8; 32]) -> u64 {
        let mut balance: i32 = 0;

        for block in &self.chain {
            for tx in &block.transactions {
                if tx.from_public_key == *public_key {
                    balance = balance.saturating_sub(tx.amount.try_into().unwrap());
                }
                if tx.to_public_key == *public_key {
                    balance = balance.saturating_add(tx.amount.try_into().unwrap());
                }
            }
        }

        for tx in &self.pending_transactions {
            if tx.from_public_key == *public_key {
                balance = balance.saturating_sub(tx.amount.try_into().unwrap());
            }
            if tx.to_public_key == *public_key {
                balance = balance.saturating_add(tx.amount.try_into().unwrap());
            }
        }

        balance.try_into().unwrap()
    }

    pub fn add_transaction(&mut self, transaction: Transaction) -> Result<(), String> {
        if !transaction.verify_signature()? {
            return Err("Invalid transaction signature".to_string());
        }

        let sender_balance = self.get_wallet_balance(&transaction.from_public_key);
        if sender_balance < transaction.amount {
            return Err("Insufficient balance".to_string());
        }

        self.pending_transactions.push(transaction);
        Ok(())
    }

    pub fn mine_pending_transactions(&mut self, miner_reward_address: [u8; 32]) {
        if self.pending_transactions.is_empty() {
            return;
        }

        let reward_tx = Transaction {
            from_public_key: [0; 32], 
            to_public_key: miner_reward_address,
            amount: 50,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            signature: None, 
        };

        let mut block_transactions = self.pending_transactions.clone();
        block_transactions.push(reward_tx);

        let prev_block = self.chain.last().unwrap();
        let new_block = self.create_block(
            prev_block.index + 1,
            block_transactions,
            prev_block.hash.clone(),
        );

        self.chain.push(new_block);
        self.pending_transactions = Vec::new();
    }

    fn create_block(&self, index: i32, transactions: Vec<Transaction>, prev_hash: String) -> Block {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nonce = 0;
        let mut hash;

        loop {
            let hash_input = self.prepare_hash_input(index, timestamp, &transactions, &prev_hash, nonce);
            hash = calculate_hash(&hash_input);
            
            // Simple PoW, hash with 4 leading zeros
            if hash.starts_with("0000") {
                break;
            }
            
            nonce += 1;
        }

        Block {
            index,
            timestamp,
            transactions,
            prev_hash,
            hash,
            nonce,
        }
    }

    fn prepare_hash_input(&self, index: i32, timestamp: u64, transactions: &Vec<Transaction>, 
                        prev_hash: &str, nonce: u64) -> String {
        let tx_data: String = transactions
            .iter()
            .map(|tx| {
                let from_key = hex::encode(&tx.from_public_key);
                let to_key = hex::encode(&tx.to_public_key);
                format!("{}->{}:{}", from_key, to_key, tx.amount)
            })
            .collect::<Vec<_>>()
            .join(";");

        format!("{}{}{}{}{}", index, timestamp, tx_data, prev_hash, nonce)
    }

    pub fn is_chain_valid(&self) -> bool {
        for i in 1..self.chain.len() {
            let current_block = &self.chain[i];
            let previous_block = &self.chain[i - 1];

            let hash_input = self.prepare_hash_input(
                current_block.index,
                current_block.timestamp,
                &current_block.transactions,
                &current_block.prev_hash,
                current_block.nonce,
            );

            if current_block.hash != calculate_hash(&hash_input) {
                return false;
            }

            if current_block.prev_hash != previous_block.hash {
                return false;
            }

            for tx in &current_block.transactions {
                if tx.from_public_key == [0; 32] {
                    continue;
                }

                match tx.verify_signature() {
                    Ok(valid) => {
                        if !valid {
                            return false;
                        }
                    },
                    Err(_) => return false,
                }
            }
        }

        true
    }
}

fn calculate_hash(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    format!("{:x}", hash)
}

fn main() {
    let mut blockchain = Blockchain::new();

    let alice = Wallet::new("Alice".to_string(), 1000);
    let bob = Wallet::new("Bob".to_string(), 0);
    let charlie = Wallet::new("Charlie".to_string(), 500);
    
    blockchain.register_wallet(alice.clone());
    blockchain.register_wallet(bob.clone());
    blockchain.register_wallet(charlie.clone());

    let funding_tx_alice = Transaction {
        from_public_key: [0; 32], // System/genesis transaction 
        to_public_key: alice.public_key_bytes(),
        amount: 1000, // Alice's init balance
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        signature: None, // sys transactions don't need sig
    };
    
    let funding_tx_charlie = Transaction {
        from_public_key: [0; 32], 
        to_public_key: charlie.public_key_bytes(),
        amount: 500,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        signature: None,
    };
    
    blockchain.pending_transactions.push(funding_tx_alice);
    blockchain.pending_transactions.push(funding_tx_charlie);
    
    blockchain.mine_pending_transactions(bob.public_key_bytes());
    
    println!("Initial wallet balances:");
    println!("Alice's balance: {}", blockchain.get_wallet_balance(&alice.public_key_bytes()));
    println!("Bob's balance: {}", blockchain.get_wallet_balance(&bob.public_key_bytes()));
    println!("Charlie's balance: {}", blockchain.get_wallet_balance(&charlie.public_key_bytes()));

    let mut tx1 = Transaction::new(&alice, &bob, 100);
    match tx1.sign(&alice) {
        Ok(_) => println!("Transaction signed successfully"),
        Err(e) => println!("Failed to sign transaction: {}", e),
    }

    match blockchain.add_transaction(tx1) {
        Ok(_) => println!("Transaction added to pending transactions"),
        Err(e) => println!("Failed to add transaction: {}", e),
    }

    let mut tx2 = Transaction::new(&charlie, &alice, 50);
    match tx2.sign(&charlie) {
        Ok(_) => println!("Transaction signed successfully"),
        Err(e) => println!("Failed to sign transaction: {}", e),
    }

    match blockchain.add_transaction(tx2) {
        Ok(_) => println!("Transaction added to pending transactions"),
        Err(e) => println!("Failed to add transaction: {}", e),
    }

    blockchain.mine_pending_transactions(bob.public_key_bytes());

    println!("\nBlockchain state:");
    for (i, block) in blockchain.chain.iter().enumerate() {
        println!("Block #{}: Hash: {}", i, block.hash);
        println!("  Transactions: {}", block.transactions.len());
        for tx in &block.transactions {
            let from = if tx.from_public_key == [0; 32] {
                "SYSTEM (Mining Reward)".to_string()
            } else {
                blockchain.find_wallet_by_public_key(&tx.from_public_key)
                    .map(|w| w.owner.clone())
                    .unwrap_or_else(|| "Unknown".to_string())
            };

            let to = blockchain.find_wallet_by_public_key(&tx.to_public_key)
                .map(|w| w.owner.clone())
                .unwrap_or_else(|| "Unknown".to_string());

            println!("    {} -> {}: {} coins", from, to, tx.amount);
        }
    }

    println!("\nWallet balances after transactions:");
    println!("Alice's balance: {}", blockchain.get_wallet_balance(&alice.public_key_bytes()));
    println!("Bob's balance: {}", blockchain.get_wallet_balance(&bob.public_key_bytes()));
    println!("Charlie's balance: {}", blockchain.get_wallet_balance(&charlie.public_key_bytes()));

    println!("\nIs blockchain valid? {}", blockchain.is_chain_valid());
}
