import { ERR_UNSTAKED, oneRBTC } from '../utils';
import chai, { assert, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { mine } from '@nomicfoundation/hardhat-network-helpers';
import { ethers } from 'hardhat';
import { FakeContract, MockContract, smock } from '@defi-wonderland/smock';
import {
  Penalizer,
  RelayHub,
  SmartWallet,
  SmartWalletFactory,
  ERC20,
  SmartWalletFactory__factory,
  SmartWallet__factory,
} from '../../typechain-types';
import { createContractDeployer } from './utils';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import {
  getLocalEip712Signature,
  TypedRequestData,
  RelayRequest,
  ForwardRequest,
  RelayData,
  DeployRequest,
  TypedDeployRequestData,
  getLocalEip712DeploySignature,
} from '../utils/EIP712Utils';
import { IForwarder } from 'typechain-types/contracts/RelayHub';
import { Wallet } from 'ethers';
import { deployContract } from '../../utils/deployment/deployment.utils';
import { HARDHAT_CHAIN_ID } from '../smartwallet/utils';
import { createValidPersonalSignSignature } from '../utils/createValidPersonalSignSignature';

chai.use(smock.matchers);
chai.use(chaiAsPromised);

const ZERO_ADDRESS = ethers.constants.AddressZero;

type SmartWalletFactoryOptions = Parameters<
  SmartWalletFactory__factory['deploy']
>;

describe('RelayHub contract - Manager related scenarios', function () {
  let deployRelayHubContract: ReturnType<typeof createContractDeployer>;
  let relayManager: SignerWithAddress, relayManagerAddr: string;
  let relayWorker: SignerWithAddress, relayWorkerAddr: string;
  let relayOwner: SignerWithAddress, relayOwnerAddr: string;
  let anotherRelayManager: SignerWithAddress;

  let fakePenalizer: FakeContract<Penalizer>;
  let mockRelayHub: MockContract<RelayHub>;

  beforeEach(async function () {
    [relayOwner, relayManager, relayWorker, anotherRelayManager] =
      (await ethers.getSigners()) as [
        SignerWithAddress,
        SignerWithAddress,
        SignerWithAddress,
        SignerWithAddress
      ];
    relayManagerAddr = relayManager.address;
    relayWorkerAddr = relayWorker.address;
    relayOwnerAddr = relayOwner.address;

    fakePenalizer = await smock.fake('Penalizer');
  });

  afterEach(function () {
    mockRelayHub = undefined as unknown as MockContract<RelayHub>;
  });

  describe('Manager tests - Stake related scenarios', function () {
    beforeEach(async function () {
      deployRelayHubContract = createContractDeployer(fakePenalizer.address);
      mockRelayHub = await deployRelayHubContract();
    });

    it('Should fail when sender is a RelayManager', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: oneRBTC,
        from: relayOwnerAddr,
      });

      await assert.isRejected(
        mockRelayHub
          .connect(relayManager)
          .stakeForAddress(anotherRelayManager.address, 1000, {
            value: oneRBTC,
            from: relayManagerAddr,
          }),
        'sender is a relayManager itself',
        'Stake was made with less value than the minimum'
      );
    });
  });

  describe('Manager - RelayRequest scenarios', function () {
    const HARDHAT_CHAIN_ID = 31337;
    let token: FakeContract<ERC20>;
    let smartWallet: FakeContract<SmartWallet>;
    let externalWallet: Wallet;

    function createRequest(
      request: Partial<ForwardRequest>,
      relayData: Partial<RelayData>
    ): RelayRequest {
      const baseRequest: RelayRequest = {
        request: {
          relayHub: ZERO_ADDRESS,
          from: ZERO_ADDRESS,
          to: ZERO_ADDRESS,
          tokenContract: ZERO_ADDRESS,
          value: '0',
          gas: '10000',
          nonce: '0',
          tokenAmount: '1',
          tokenGas: '50000',
          validUntilTime: '0',
          data: '0x',
        } as ForwardRequest,
        relayData: {
          gasPrice: '1',
          feesReceiver: ZERO_ADDRESS,
          callForwarder: ZERO_ADDRESS,
          callVerifier: ZERO_ADDRESS,
        } as RelayData,
      } as RelayRequest;

      return {
        request: {
          ...baseRequest.request,
          ...request,
        },
        relayData: {
          ...baseRequest.relayData,
          ...relayData,
        },
      };
    }

    beforeEach(async function () {
      deployRelayHubContract = createContractDeployer(fakePenalizer.address);
      mockRelayHub = await deployRelayHubContract();
      token = await smock.fake('ERC20');
      token.transfer.returns(true);

      smartWallet = await smock.fake('SmartWallet');
      externalWallet = ethers.Wallet.createRandom();
      externalWallet.connect(ethers.provider);
    });

    afterEach(function () {
      mockRelayHub = undefined as unknown as MockContract<RelayHub>;
    });

    it('Should fail a relayRequest if the manager is in the last block of delay blocks', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: oneRBTC,
        from: relayOwnerAddr,
      });

      await mockRelayHub
        .connect(relayManager)
        .addRelayWorkers([relayWorkerAddr]);
      await mockRelayHub.workerToManager(relayWorkerAddr);

      await mockRelayHub.unlockStake(relayManagerAddr, {
        from: relayOwnerAddr,
      });

      const relayRequest = createRequest(
        {
          from: externalWallet.address,
          tokenContract: token.address,
          relayHub: mockRelayHub.address,
          tokenAmount: '1',
          tokenGas: '50000',
        },
        {
          feesReceiver: relayWorkerAddr,
        }
      );

      const typedRequestData = new TypedRequestData(
        HARDHAT_CHAIN_ID,
        smartWallet.address,
        relayRequest
      );

      const privateKey = Buffer.from(
        externalWallet.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712Signature(typedRequestData, privateKey);
      //
      mockRelayHub = mockRelayHub.connect(relayWorker);
      await expect(
        mockRelayHub.relayCall(relayRequest, signature)
      ).to.be.rejectedWith(ERR_UNSTAKED);
    });

    it('Should fail a relayRequest if the manager is unstaked', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: oneRBTC,
        from: relayOwnerAddr,
      });

      let relayWorkersBefore = await mockRelayHub.workerCount(relayManagerAddr);

      assert.equal(
        relayWorkersBefore.toNumber(),
        0,
        `Initial workers must be zero but was ${relayWorkersBefore.toNumber()}`
      );

      await mockRelayHub
        .connect(relayManager)
        .addRelayWorkers([relayWorkerAddr], {
          from: relayManagerAddr,
        });
      await mockRelayHub.workerToManager(relayWorkerAddr);

      await mockRelayHub.unlockStake(relayManagerAddr, {
        from: relayOwnerAddr,
      });

      //Verifying stake is now unlocked
      let stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);
      const isUnlocked = Number(stakeInfo.withdrawBlock) > 0;
      assert.isTrue(isUnlocked, 'Stake is not unlocked');

      //Moving blocks to be able to unstake
      await mine(Number(stakeInfo.unstakeDelay));
      await ethers.provider.send('evm_increaseTime', [
        Number(stakeInfo.unstakeDelay),
      ]);
      await ethers.provider.send('evm_mine', []);

      stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);
      const stakeBalanceBefore = ethers.BigNumber.from(stakeInfo.stake);

      const relayOwnerBalanceBefore = ethers.BigNumber.from(
        await ethers.provider.getBalance(relayOwnerAddr)
      );

      const gasPrice = ethers.BigNumber.from('6000000000000');
      const txResponse = await mockRelayHub.withdrawStake(relayManagerAddr, {
        from: relayOwnerAddr,
        gasPrice,
      });

      //Getting the gas used in order to calculate the original balance of the account

      const txReceipt = await ethers.provider.getTransactionReceipt(
        txResponse.hash
      );
      const rbtcUsed = ethers.BigNumber.from(txReceipt.cumulativeGasUsed).mul(
        gasPrice
      );

      const relayOwnerBalanceAfter = ethers.BigNumber.from(
        await ethers.provider.getBalance(relayOwnerAddr)
      );
      assert.isTrue(
        relayOwnerBalanceAfter.eq(
          relayOwnerBalanceBefore.sub(rbtcUsed).add(stakeBalanceBefore)
        ),
        'Withdraw/unstake process have failed'
      );

      stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);
      const stakeAfterWithdraw = ethers.BigNumber.from(stakeInfo.stake);

      //Verifying there are no more stake balance for the manager
      assert.isTrue(stakeAfterWithdraw.isZero(), 'Stake must be zero');

      relayWorkersBefore = await mockRelayHub.workerCount(relayManagerAddr);
      assert.equal(
        relayWorkersBefore.toNumber(),
        1,
        `Initial workers must be zero but was ${relayWorkersBefore.toNumber()}`
      );

      const relayRequest = createRequest(
        {
          from: externalWallet.address,
          tokenContract: token.address,
          relayHub: mockRelayHub.address,
          tokenAmount: '1',
          tokenGas: '6000000000000',
        },
        {
          feesReceiver: relayWorkerAddr,
        }
      );

      relayRequest.request.data = '0xdeadbeef';

      const typedRequestData = new TypedRequestData(
        HARDHAT_CHAIN_ID,
        smartWallet.address,
        relayRequest
      );

      const privateKey = Buffer.from(
        externalWallet.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712Signature(typedRequestData, privateKey);

      await assert.isRejected(
        mockRelayHub.connect(relayWorker).relayCall(relayRequest, signature),
        ERR_UNSTAKED,
        'Relay request was properly processed'
      );
    });
  });

  describe('Manager - DeployRequest scenarios', function () {
    const url = 'http://relay.com';

    const HARDHAT_CHAIN_ID = 31337;
    let token: FakeContract<ERC20>;
    let smartWallet: FakeContract<SmartWallet>;
    let externalWallet: Wallet;
    const nextWalletIndex = 500;

    function createRequest(
      request: Partial<IForwarder.DeployRequestStruct>,
      relayData: Partial<RelayData>
    ): DeployRequest {
      const baseRequest: DeployRequest = {
        request: {
          relayHub: ZERO_ADDRESS,
          from: ZERO_ADDRESS,
          to: ZERO_ADDRESS,
          tokenContract: ZERO_ADDRESS,
          value: '0',
          nonce: '0',
          tokenAmount: '1',
          tokenGas: '50000',
          data: '0x',
          recoverer: '0',
          validUntilTime: '0',
          index: 0,
        },
        relayData: {
          gasPrice: '1',
          feesReceiver: ZERO_ADDRESS,
          callForwarder: ZERO_ADDRESS,
          callVerifier: ZERO_ADDRESS,
        },
      };

      return {
        request: {
          ...baseRequest.request,
          ...request,
        },
        relayData: {
          ...baseRequest.relayData,
          ...relayData,
        },
      };
    }

    beforeEach(async function () {
      token = await smock.fake('ERC20');
      token.transfer.returns(true);

      deployRelayHubContract = createContractDeployer(fakePenalizer.address);
      mockRelayHub = await deployRelayHubContract();

      smartWallet = await smock.fake('SmartWallet');
      externalWallet = ethers.Wallet.createRandom();
      externalWallet.connect(ethers.provider);
    });

    afterEach(function () {
      mockRelayHub = undefined as unknown as MockContract<RelayHub>;
    });

    it('Should fail a deployRequest if SmartWallet has already been initialized', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: ethers.BigNumber.from(2),
        from: relayOwnerAddr,
      });

      await mockRelayHub
        .connect(relayManager)
        .addRelayWorkers([relayWorkerAddr]);
      await mockRelayHub.connect(relayManager).registerRelayServer(url);

      const smartWalletFactory: FakeContract<SmartWalletFactory> =
        await smock.fake<SmartWalletFactory>('SmartWalletFactory');
      smartWalletFactory.relayedUserSmartWalletCreation.reverts();

      const relayRequestMisbehavingVerifier = createRequest(
        {
          from: externalWallet.address,
          to: ZERO_ADDRESS,
          data: '0x',
          tokenContract: token.address,
          relayHub: mockRelayHub.address,
          tokenAmount: '1',
          tokenGas: '50000',
          recoverer: ZERO_ADDRESS,
          index: '0',
        },
        {
          feesReceiver: relayWorkerAddr,
          callForwarder: smartWalletFactory.address,
        }
      );

      relayRequestMisbehavingVerifier.request.index =
        nextWalletIndex.toString();

      const typedRequestData = new TypedDeployRequestData(
        HARDHAT_CHAIN_ID,
        smartWalletFactory.address,
        relayRequestMisbehavingVerifier
      );

      const privateKey = Buffer.from(
        externalWallet.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712DeploySignature(
        typedRequestData,
        privateKey
      );

      await assert.isRejected(
        mockRelayHub
          .connect(relayWorker)
          .deployCall(relayRequestMisbehavingVerifier, signature),
        'Transaction reverted without a reason string',
        'SW was deployed and initialized'
      );
    });

    it('Should fail a deployRequest if Manager is unstaked', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: oneRBTC,
        from: relayOwnerAddr,
      });

      let relayWorkersBefore = await mockRelayHub.workerCount(relayManagerAddr);

      assert.equal(
        relayWorkersBefore.toNumber(),
        0,
        `Initial workers must be zero but was ${relayWorkersBefore.toNumber()}`
      );

      await mockRelayHub
        .connect(relayManager)
        .addRelayWorkers([relayWorkerAddr], {
          from: relayManagerAddr,
        });

      await mockRelayHub.workerToManager(relayWorkerAddr);

      await mockRelayHub.unlockStake(relayManagerAddr, {
        from: relayOwnerAddr,
      });

      //Verifying stake is now unlocked
      let stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);

      //Moving blocks to be able to unstake
      await mine(Number(stakeInfo.unstakeDelay));

      stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);
      const stakeBalanceBefore = ethers.BigNumber.from(stakeInfo.stake);

      const relayOwnerBalanceBefore = ethers.BigNumber.from(
        await ethers.provider.getBalance(relayOwnerAddr)
      );

      const gasPrice = ethers.BigNumber.from('351981441');
      const txResponse = await mockRelayHub.withdrawStake(relayManagerAddr, {
        from: relayOwnerAddr,
        gasPrice,
      });

      //Getting the gas used in order to calculate the original balance of the account
      const txReceipt = await ethers.provider.getTransactionReceipt(
        txResponse.hash
      );
      const rbtcUsed = ethers.BigNumber.from(txReceipt.cumulativeGasUsed).mul(
        gasPrice
      );

      const relayOwnerBalanceAfter = ethers.BigNumber.from(
        await ethers.provider.getBalance(relayOwnerAddr)
      );
      assert.isTrue(
        relayOwnerBalanceAfter.eq(
          relayOwnerBalanceBefore.sub(rbtcUsed).add(stakeBalanceBefore)
        ),
        'Withdraw/unstake process have failed'
      );

      stakeInfo = await mockRelayHub.getStakeInfo(relayManagerAddr);
      const stakeAfterWithdraw = ethers.BigNumber.from(stakeInfo.stake);

      //Verifying there are no more stake balance for the manager
      assert.isTrue(stakeAfterWithdraw.isZero(), 'Stake must be zero');

      relayWorkersBefore = await mockRelayHub.workerCount(relayManagerAddr);
      assert.equal(
        relayWorkersBefore.toNumber(),
        1,
        `Initial workers must be zero but was ${relayWorkersBefore.toNumber()}`
      );

      const relayRequestMisbehavingVerifier = createRequest(
        {
          from: externalWallet.address,
          to: ZERO_ADDRESS,
          data: '0x',
          tokenContract: token.address,
          relayHub: mockRelayHub.address,
          tokenAmount: '1',
          tokenGas: '50000',
          recoverer: ZERO_ADDRESS,
          index: '0',
        },
        {
          feesReceiver: relayWorkerAddr,
        }
      );

      relayRequestMisbehavingVerifier.request.index =
        nextWalletIndex.toString();

      const typedRequestData = new TypedDeployRequestData(
        HARDHAT_CHAIN_ID,
        smartWallet.address,
        relayRequestMisbehavingVerifier
      );

      const privateKey = Buffer.from(
        externalWallet.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712DeploySignature(
        typedRequestData,
        privateKey
      );

      await assert.isRejected(
        mockRelayHub
          .connect(relayWorker)
          .deployCall(relayRequestMisbehavingVerifier, signature),
        ERR_UNSTAKED,
        'Deploy was processed successfully'
      );
    });

    it('Should fail when registering with no workers assigned to the Manager', async function () {
      await mockRelayHub.stakeForAddress(relayManagerAddr, 1000, {
        value: oneRBTC,
        from: relayOwnerAddr,
      });

      const relayWorkersBefore = await mockRelayHub.workerCount(
        relayManagerAddr
      );

      assert.equal(
        relayWorkersBefore.toNumber(),
        0,
        `Initial workers must be zero but was ${relayWorkersBefore.toNumber()}`
      );

      await assert.isRejected(
        mockRelayHub.connect(relayManager).registerRelayServer(url, {
          from: relayManagerAddr,
        }),
        'no relay workers',
        'Relay Server was successfully registered'
      );
    });
  });
});

describe.only('RelayHub', function () {
  const url = 'http://relay.com';
  const environment = 33; // RSK = 33 | HARDHAT = HARDHAT_CHAIN_ID
  let penalizer: Penalizer;
  let relayHub: RelayHub;
  let relayManager: SignerWithAddress;
  let relayWorker: Wallet;
  let relayOwner: SignerWithAddress;
  let smartWalletFactory: SmartWalletFactory;

  beforeEach(async function () {
    [relayOwner, relayManager] = (await ethers.getSigners()) as [
      SignerWithAddress,
      SignerWithAddress
    ];
    relayWorker = Wallet.createRandom().connect(ethers.provider);
    relayOwner.sendTransaction({
      to: relayWorker.address,
      value: ethers.utils.parseEther('1'),
    });
    ({ contract: penalizer } = await deployContract<Penalizer, []>({
      contractName: 'Penalizer',
      constructorArgs: [],
    }));
    const relayHubFactory = await ethers.getContractFactory('RelayHub');
    relayHub = await relayHubFactory.deploy(penalizer.address, 1, 1, 10, 1);
    await relayHub.stakeForAddress(relayManager.address, 1000, {
      value: ethers.BigNumber.from(2),
      from: relayOwner.address,
    });

    await relayHub.connect(relayManager).addRelayWorkers([relayWorker.address]);
    await relayHub.connect(relayManager).registerRelayServer(url);

    const { contract: template } = await deployContract<SmartWallet, []>({
      contractName: 'SmartWallet',
      constructorArgs: [],
    });
    console.log('-------------template');
    console.log(template.address);
    console.log('-------------template');
    ({ contract: smartWalletFactory } = await deployContract<
      SmartWalletFactory,
      SmartWalletFactoryOptions
    >({
      contractName: 'SmartWalletFactory',
      constructorArgs: [template.address],
    }));
    console.log('-------------factory');
    console.log(smartWalletFactory.address);
    console.log('-------------factory');
    console.log('-------------relayHub');
    console.log(relayHub.address);
    console.log('-------------relayHub');
  });

  describe('serverDeployCall', function () {
    function createRequest(
      request: Partial<IForwarder.DeployRequestStruct>,
      relayData: Partial<RelayData>
    ): DeployRequest {
      const baseRequest: DeployRequest = {
        request: {
          relayHub: ZERO_ADDRESS,
          from: ZERO_ADDRESS,
          to: ZERO_ADDRESS,
          tokenContract: ZERO_ADDRESS,
          value: '0',
          nonce: '0',
          tokenAmount: '0',
          tokenGas: '0',
          data: '0x',
          recoverer: ZERO_ADDRESS,
          validUntilTime: '0',
          index: 0,
        },
        relayData: {
          gasPrice: '1',
          feesReceiver: ZERO_ADDRESS,
          callForwarder: ZERO_ADDRESS,
          callVerifier: ZERO_ADDRESS,
        },
      };

      return {
        request: {
          ...baseRequest.request,
          ...request,
        },
        relayData: {
          ...baseRequest.relayData,
          ...relayData,
        },
      };
    }

    it('', async function () {
      const deployRequest = createRequest(
        {
          from: relayWorker.address,
          relayHub: relayHub.address,
          recoverer: ZERO_ADDRESS,
          index: '0',
        },
        {
          callForwarder: smartWalletFactory.address,
        }
      );

      const typedRequestData = new TypedDeployRequestData(
        environment,
        smartWalletFactory.address,
        deployRequest
      );

      const privateKey = Buffer.from(
        relayWorker.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712DeploySignature(
        typedRequestData,
        privateKey
      );

      //const tx1 = await mockRelayHub.connect(relayWorker).serverDeployCall(deployRequest, signature, { gasPrice: 1 });
      const estimation = await relayHub
        .connect(relayWorker)
        .estimateGas.serverDeployCall(deployRequest, signature, {
          gasPrice: 1,
        });
      const tx2 = await relayHub
        .connect(relayWorker)
        .deployCall(deployRequest, signature, { gasPrice: 1 });

      //const receipt1 = await tx1.wait();
      const receipt2 = await tx2.wait();

      // console.log(tx1);

      console.log(
        estimation
          .add(20300) //nonce increase
          .add(41000) // create2
          .add(753) // minimal proxy call
          .add(39) // calldata cost
          .add(700) // smart wallet call
          .add(20300) // set owner
          .add(2100) // IDK
          .add(20300) // domainSeparator
          .add(1500) // emit Deployed
          .toString()
      );
      // console.log(receipt1.gasUsed.toString())
      console.log(receipt2.gasUsed.toString());

      /*   const iface = SmartWallet__factory.createInterface();

      console.log('--------');
      console.log(iface.parseLog(receipt2.logs[0])); */
    });
  });

  describe.only('serverRelayCall', function () {
    function createRequest(
      request: Partial<IForwarder.ForwardRequestStruct>,
      relayData: Partial<RelayData>
    ): RelayRequest {
      const baseRequest: RelayRequest = {
        request: {
          relayHub: ZERO_ADDRESS,
          from: ZERO_ADDRESS,
          to: ZERO_ADDRESS,
          tokenContract: ZERO_ADDRESS,
          value: '0',
          nonce: '0',
          tokenAmount: '0',
          tokenGas: '0',
          data: '0x',
          validUntilTime: '0',
          gas: '0',
        },
        relayData: {
          gasPrice: '1',
          feesReceiver: ZERO_ADDRESS,
          callForwarder: ZERO_ADDRESS,
          callVerifier: ZERO_ADDRESS,
        },
      };

      return {
        request: {
          ...baseRequest.request,
          ...request,
        },
        relayData: {
          ...baseRequest.relayData,
          ...relayData,
        },
      };
    }

    let smartWallet: SmartWallet;

    beforeEach(async function () {
      const dataTypesToSign = ['address', 'address', 'address', 'uint256'];
      const valuesToSign = [
        smartWalletFactory.address,
        relayWorker.address,
        ZERO_ADDRESS,
        0,
      ];
      const toSign = ethers.utils.solidityKeccak256(
        dataTypesToSign,
        valuesToSign
      );

      const privateKey = Buffer.from(
        relayWorker.privateKey.substring(2, 66),
        'hex'
      );
      const signature = createValidPersonalSignSignature(privateKey, toSign);

      await smartWalletFactory.createUserSmartWallet(
        relayWorker.address,
        ZERO_ADDRESS,
        '0',
        signature
      );

      const smartWalletAddress = await smartWalletFactory.getSmartWalletAddress(
        relayWorker.address,
        ZERO_ADDRESS,
        0
      );

      smartWallet = await ethers.getContractAt(
        'SmartWallet',
        smartWalletAddress
      );
    });

    it('', async function () {
      const relayRequest = createRequest(
        {
          from: relayWorker.address,
          relayHub: relayHub.address,
          gas: 500,
        },
        {
          callForwarder: smartWallet.address,
        }
      );

      const typedRequestData = new TypedRequestData(
        environment,
        smartWallet.address,
        relayRequest
      );

      const privateKey = Buffer.from(
        relayWorker.privateKey.substring(2, 66),
        'hex'
      );

      const signature = getLocalEip712DeploySignature(
        typedRequestData,
        privateKey
      );

      const estimation = await relayHub
        .connect(relayWorker)
        .estimateGas.serverRelayCall(relayRequest, signature, { gasPrice: 1 });
      const tx2 = await relayHub
        .connect(relayWorker)
        .relayCall(relayRequest, signature, { gasPrice: 1 });

      const receipt2 = await tx2.wait();

      console.log('-----------');
      console.log(
        estimation
          .add(4000) // initial buffer
          .add(20300) //nonce increase
          .toString()
      );
      console.log(receipt2.gasUsed.toString());

      /*  const iface = SmartWallet__factory.createInterface();

      console.log('--------');
      console.log(iface.parseLog(receipt2.logs[0]));
      console.log(iface.parseLog(receipt2.logs[1]));
      console.log(iface.parseLog(receipt2.logs[2]));
      console.log('--------'); */
      //iface.parseLog(receipt2.logs[3]);
    });
  });
});
