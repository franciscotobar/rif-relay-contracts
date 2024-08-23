import { expect } from 'chai';
import {
  SmartWallet,
  SmartWalletFactory,
  SmartWalletFactory__factory,
  UtilToken,
} from 'typechain-types';
import { ethers } from 'hardhat';
import { constants, utils, Wallet } from 'ethers';
import { SignerWithAddress } from '@nomiclabs/hardhat-ethers/signers';
import { createValidPersonalSignSignature } from '../utils/createValidPersonalSignSignature';
import { createDeployRequest, randomNumber, signDeployRequest } from './utils';
import { deployContract } from '../../utils/deployment/deployment.utils';

type SmartWalletFactoryOptions = Parameters<
  SmartWalletFactory__factory['deploy']
>;

describe('SmartWalletFactory', function () {
  let chainId: number;

  before(async function () {
    ({ chainId } = await ethers.provider.getNetwork());
  });

  describe('constructor', function () {
    let smartWalletFactory: SmartWalletFactory;
    let template: Wallet;

    beforeEach(async function () {
      template = ethers.Wallet.createRandom();
      ({ contract: smartWalletFactory } = await deployContract<
        SmartWalletFactory,
        SmartWalletFactoryOptions
      >({
        contractName: 'SmartWalletFactory',
        constructorArgs: [template.address],
      }));
    });

    it('should update master copy', async function () {
      await expect(smartWalletFactory.masterCopy()).to.eventually.be.equal(
        template.address
      );
    });
  });

  describe('methods', function () {
    let smartWalletFactory: SmartWalletFactory;
    let owner: Wallet;

    beforeEach(async function () {
      const { contract: template } = await deployContract<SmartWallet, []>({
        contractName: 'SmartWallet',
        constructorArgs: [],
      });
      ({ contract: smartWalletFactory } = await deployContract<
        SmartWalletFactory,
        SmartWalletFactoryOptions
      >({
        contractName: 'SmartWalletFactory',
        constructorArgs: [template.address],
      }));
      owner = ethers.Wallet.createRandom();
    });

    describe('createUserSmartWallet', function () {
      let recoverer: string;
      let index: number;

      beforeEach(function () {
        recoverer = constants.AddressZero;
        index = randomNumber();
      });

      it('should initiate the smart wallet in the expected address', async function () {
        const smartWalletAddress =
          await smartWalletFactory.getSmartWalletAddress(
            owner.address,
            recoverer,
            index
          );

        const dataToSign = utils.solidityKeccak256(
          ['address', 'address', 'address', 'uint256'],
          [smartWalletFactory.address, owner.address, recoverer, index]
        );

        const privateKey = Buffer.from(
          owner.privateKey.substring(2, 66),
          'hex'
        );

        const signature = createValidPersonalSignSignature(
          privateKey,
          dataToSign
        );

        await smartWalletFactory.createUserSmartWallet(
          owner.address,
          recoverer,
          index,
          signature
        );

        const smartWallet = await ethers.getContractAt(
          'SmartWallet',
          smartWalletAddress
        );

        expect(smartWallet.address).to.be.equal(smartWalletAddress);
        await expect(smartWallet.isInitialized()).to.eventually.be.true;
      });

      it('should fail with a ZERO owner address parameter', async function () {
        const dataToSign = utils.solidityKeccak256(
          ['address', 'address', 'address', 'uint256'],
          [smartWalletFactory.address, constants.AddressZero, recoverer, index]
        );

        const privateKey = Buffer.from(
          owner.privateKey.substring(2, 66),
          'hex'
        );

        const signature = createValidPersonalSignSignature(
          privateKey,
          dataToSign
        );

        await expect(
          smartWalletFactory.createUserSmartWallet(
            constants.AddressZero,
            recoverer,
            index,
            signature
          )
        ).to.be.rejectedWith('Invalid signature');
      });

      it('should fail when signature does not match', async function () {
        const dataToSign = utils.solidityKeccak256(
          ['address', 'address', 'address', 'uint256'],
          [smartWalletFactory.address, owner.address, recoverer, index]
        );

        const privateKey = Buffer.from(
          owner.privateKey.substring(2, 66),
          'hex'
        );

        const signature = createValidPersonalSignSignature(
          privateKey,
          dataToSign
        );

        const otherAccount = Wallet.createRandom();

        await expect(
          smartWalletFactory.createUserSmartWallet(
            otherAccount.address,
            recoverer,
            index,
            signature
          )
        ).to.be.rejectedWith('Invalid signature');
      });
    });

    describe('relayedUserSmartWalletCreation', function () {
      let recoverer: string;
      let index: number;
      let smartWalletAddress: string;
      let worker: SignerWithAddress;
      let token: UtilToken;
      const tokenGas = 55000;

      beforeEach(async function () {
        recoverer = constants.AddressZero;
        index = randomNumber();
        smartWalletAddress = await smartWalletFactory.getSmartWalletAddress(
          owner.address,
          recoverer,
          index
        );
        [worker] = await ethers.getSigners();
        ({ contract: token } = await deployContract<UtilToken, []>({
          contractName: 'UtilToken',
          constructorArgs: [],
        }));
        await token.mint(utils.parseEther('5'), smartWalletAddress);
      });

      it('should initialize the smart wallet in the expected address without paying fee', async function () {
        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: 0,
            tokenGas: 0,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await smartWalletFactory
          .connect(worker)
          .relayedUserSmartWalletCreation(
            deployRequest.request,
            suffixData,
            worker.address,
            signature
          );

        const smartWallet = await ethers.getContractAt(
          'SmartWallet',
          smartWalletAddress
        );

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
        await expect(smartWallet.isInitialized()).to.eventually.be.true;
      });

      it('should initialize the smart wallet in the expected address paying fee', async function () {
        const amountToPay = utils.parseEther('2').toString();

        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: amountToPay,
            tokenGas,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await smartWalletFactory
          .connect(worker)
          .relayedUserSmartWalletCreation(
            deployRequest.request,
            suffixData,
            worker.address,
            signature
          );

        const smartWallet = await ethers.getContractAt(
          'SmartWallet',
          smartWalletAddress
        );

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(
          initialWorkerBalance.add(amountToPay)
        );
        await expect(smartWallet.isInitialized()).to.eventually.be.true;
      });

      it('should fail with tokenGas equals to zero while paying fee', async function () {
        const amountToPay = utils.parseEther('2').toString();

        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: amountToPay,
            tokenGas: 0,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await expect(
          smartWalletFactory
            .connect(worker)
            .relayedUserSmartWalletCreation(
              deployRequest.request,
              suffixData,
              worker.address,
              signature
            )
        ).to.be.rejectedWith('Unable to initialize SW');

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
      });

      it('should fail when the smart wallet does not have funds to pay', async function () {
        const amountToPay = utils.parseEther('6').toString();

        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: amountToPay,
            tokenGas,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await expect(
          smartWalletFactory
            .connect(worker)
            .relayedUserSmartWalletCreation(
              deployRequest.request,
              suffixData,
              worker.address,
              signature
            )
        ).to.be.rejectedWith('Unable to initialize SW');

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
      });

      it('should fail when invalid caller(Not relayHub)', async function () {
        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: 0,
            tokenGas: 0,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        const invalidRelayHub = (await ethers.getSigners()).at(
          1
        ) as SignerWithAddress;

        await expect(
          smartWalletFactory
            .connect(invalidRelayHub)
            .relayedUserSmartWalletCreation(
              deployRequest.request,
              suffixData,
              worker.address,
              signature
            )
        ).to.be.rejectedWith('Invalid caller');

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
      });

      it('should fail when nonce does not match', async function () {
        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: 0,
            tokenGas: 0,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
            nonce: 1,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await expect(
          smartWalletFactory
            .connect(worker)
            .relayedUserSmartWalletCreation(
              deployRequest.request,
              suffixData,
              worker.address,
              signature
            )
        ).to.be.rejectedWith('nonce mismatch');

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
      });

      it('should fail when signature does not match', async function () {
        const deployRequest = createDeployRequest(
          {
            from: owner.address,
            tokenContract: token.address,
            tokenAmount: 0,
            tokenGas: 0,
            recoverer: recoverer,
            index: index,
            relayHub: worker.address,
          },
          {
            callForwarder: smartWalletFactory.address,
          }
        );

        const { suffixData, signature } = signDeployRequest(
          owner,
          deployRequest,
          smartWalletFactory.address,
          chainId
        );

        const otherAccount = Wallet.createRandom();

        deployRequest.request.from = otherAccount.address;

        const initialWorkerBalance = await token.balanceOf(worker.address);

        await expect(
          smartWalletFactory
            .connect(worker)
            .relayedUserSmartWalletCreation(
              deployRequest.request,
              suffixData,
              worker.address,
              signature
            )
        ).to.be.rejectedWith('Signature mismatch');

        const finalWorkerBalance = await token.balanceOf(worker.address);

        expect(finalWorkerBalance).to.be.equal(initialWorkerBalance);
      });
    });

    describe('serverUserSmartWalletCreation', function () {});
  });
});
