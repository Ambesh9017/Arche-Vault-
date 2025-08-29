// Deployment script for Bitcoin Savings DApp
// Run with: node deploy.js

const { 
    makeContractDeploy,
    broadcastTransaction,
    AnchorMode,
    PostConditionMode,
    StacksTestnet,
    StacksMainnet
} = require('@stacks/transactions');
const { readFileSync } = require('fs');
const { generateWallet, getStxAddress } = require('@stacks/wallet-sdk');

// Configuration
const NETWORK = new StacksTestnet(); // Change to StacksMainnet() for mainnet
const CONTRACT_NAME = 'recurring-savings';

async function deployContract() {
    // Load your wallet mnemonic (keep this secure!)
    const mnemonic = process.env.STACKS_MNEMONIC || 'your-wallet-mnemonic-here';
    
    if (!mnemonic || mnemonic === 'your-wallet-mnemonic-here') {
        console.error('Please set STACKS_MNEMONIC environment variable');
        process.exit(1);
    }
    
    // Generate wallet from mnemonic
    const wallet = await generateWallet({
        secretKey: mnemonic,
        password: 'password'
    });
    
    const senderAddress = getStxAddress({ account: wallet.accounts[0], transactionVersion: NETWORK.version });
    const senderKey = wallet.accounts[0].stxPrivateKey;
    
    console.log('Deploying from address:', senderAddress);
    
    // Read contract source code
    const contractSource = readFileSync('./contracts/recurring-savings.clar', 'utf8');
    
    // Create deployment transaction
    const txOptions = {
        contractName: CONTRACT_NAME,
        codeBody: contractSource,
        senderKey: senderKey,
        network: NETWORK,
        anchorMode: AnchorMode.Any,
        postConditionMode: PostConditionMode.Allow,
        fee: 10000, // Adjust fee as needed
    };
    
    try {
        console.log('Creating deployment transaction...');
        const transaction = await makeContractDeploy(txOptions);
        
        console.log('Broadcasting transaction...');
        const broadcastResponse = await broadcastTransaction(transaction, NETWORK);
        
        console.log('Deployment successful!');
        console.log('Transaction ID:', broadcastResponse.txid);
        console.log('Contract Address:', senderAddress);
        console.log('Contract Name:', CONTRACT_NAME);
        console.log('Full Contract ID:', `${senderAddress}.${CONTRACT_NAME}`);
        
        // Wait for confirmation
        console.log('\nWaiting for transaction confirmation...');
        console.log(`Check status at: ${NETWORK.coreApiUrl}/extended/v1/tx/${broadcastResponse.txid}`);
        
        return {
            txid: broadcastResponse.txid,
            contractAddress: senderAddress,
            contractName: CONTRACT_NAME
        };
        
    } catch (error) {
        console.error('Deployment failed:', error);
        throw error;
    }
}

// Verification function
async function verifyDeployment(contractAddress, contractName) {
    const contractUrl = `${NETWORK.coreApiUrl}/v2/contracts/interface/${contractAddress}/${contractName}`;
    
    try {
        const response = await fetch(contractUrl);
        if (response.ok) {
            console.log('✅ Contract deployment verified!');
            const contractInfo = await response.json();
            console.log('Contract functions:', Object.keys(contractInfo.functions));
        } else {
            console.log('⏳ Contract not yet available, may still be processing...');
        }
    } catch (error) {
        console.log('⏳ Contract verification pending...');
    }
}

// Main deployment function
async function main() {
    try {
        const deployment = await deployContract();
        
        // Wait a bit then verify
        setTimeout(() => {
            verifyDeployment(deployment.contractAddress, deployment.contractName);
        }, 30000); // Wait 30 seconds
        
    } catch (error) {
        console.error('Script failed:', error);
        process.exit(1);
    }
}

// Run deployment
if (require.main === module) {
    main();
}

module.exports = { deployContract, verifyDeployment };