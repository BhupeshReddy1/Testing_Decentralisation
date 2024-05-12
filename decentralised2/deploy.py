from brownie import accounts, config, FileVerification
#from brownie.network import gas_price
#from brownie.network.gas.strategies import LinearScalingStrategy
import os
import time
#gas_strategy = LinearScalingStrategy("60 gwei", "70 gwei", 1.1)
#gas_price(gas_strategy)
def deploy():
    account = accounts.add(config["wallets"]["from_key"])
    File_Verification = FileVerification.deploy({
        "from": account,
 #       "gas_price": gas_strategy
        })
    # Transact# Call
    print(File_Verification)
    return File_Verification

def main():
    deployed_contract = deploy()
      