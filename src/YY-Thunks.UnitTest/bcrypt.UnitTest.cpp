#include "pch.h"
#include "Thunks/bcrypt.hpp"


namespace bcrypt
{
	TEST_CLASS(BCryptGenRandom)
	{
        AwaysNullGuard Guard;

	public:
		BCryptGenRandom()
		{
            Guard |= YY::Thunks::aways_null_try_get_BCryptOpenAlgorithmProvider;
            Guard |= YY::Thunks::aways_null_try_get_BCryptCloseAlgorithmProvider;
            Guard |= YY::Thunks::aways_null_try_get_BCryptGenRandom;
		}

		TEST_METHOD(BCRYPT_USE_SYSTEM_PREFERRED_RNG模式)
		{
			UCHAR _Temp[15] = {};
			long _Status = ::BCryptGenRandom(nullptr, _Temp, sizeof(_Temp), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
			Assert::IsTrue(_Status >= 0);
			
			const UCHAR _Temp2[15] = {};
			Assert::IsFalse(memcpy(_Temp, _Temp2, sizeof(_Temp2)) == 0);
		}

		TEST_METHOD(BCryptOpen在关闭)
		{
			BCRYPT_ALG_HANDLE _hAlg = nullptr;
			auto _Status = ::BCryptOpenAlgorithmProvider(&_hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0);
			Assert::IsTrue(_Status >= 0);
			Assert::IsNotNull(_hAlg);

			UCHAR _Temp[15] = {};
			_Status = ::BCryptGenRandom(_hAlg, _Temp, sizeof(_Temp), 0);
			Assert::IsTrue(_Status >= 0);

			const UCHAR _Temp2[15] = {};
			Assert::IsFalse(memcpy(_Temp, _Temp2, sizeof(_Temp2)) == 0);

			_Status = ::BCryptCloseAlgorithmProvider(_hAlg, 0);
			Assert::IsTrue(_Status >= 0);
		}
	};

    TEST_CLASS(BCryptHash)
    {
        AwaysNullGuard Guard;
    public:
        BCryptHash()
        {
            Guard |= YY::Thunks::aways_null_try_get_BCryptOpenAlgorithmProvider;
            Guard |= YY::Thunks::aways_null_try_get_BCryptCloseAlgorithmProvider;
            Guard |= YY::Thunks::aways_null_try_get_BCryptGenRandom;
            Guard |= YY::Thunks::aways_null_try_get_BCryptCreateHash;
            Guard |= YY::Thunks::aways_null_try_get_BCryptDestroyHash;
            Guard |= YY::Thunks::aways_null_try_get_BCryptHashData;
            Guard |= YY::Thunks::aways_null_try_get_BCryptFinishHash;
        }

        template<size_t kTargetShaLength>
        static void TestHash(_In_z_ LPCWSTR _szAlgId, _In_ ULONG _fFlags, _In_ const byte (&_pTargetSha)[kTargetShaLength], const char* _szKey = nullptr)
        {
            BCRYPT_ALG_HANDLE _hAlg = nullptr;
            int _Status = ::BCryptOpenAlgorithmProvider(&_hAlg, _szAlgId, nullptr, _fFlags);
            Assert::IsTrue(_Status >= 0);
            Assert::IsNotNull(_hAlg);
            BCRYPT_HASH_HANDLE _hHash = nullptr;
            _Status = ::BCryptCreateHash(_hAlg, &_hHash, nullptr, 0, (PUCHAR)_szKey, _szKey ? strlen(_szKey) : 0, 0);
            Assert::IsTrue(_Status >= 0);
            Assert::IsNotNull(_hHash);

            _Status = ::BCryptHashData(_hHash, reinterpret_cast<PUCHAR>("123"), 3, 0);
            Assert::IsTrue(_Status >= 0);

            byte _ShaCurrent[kTargetShaLength] = {};
            _Status = ::BCryptFinishHash(_hHash, _ShaCurrent, sizeof(_ShaCurrent), 0);
            Assert::IsTrue(_Status >= 0);

            Assert::IsTrue(memcmp(_ShaCurrent, _pTargetSha, sizeof(kTargetShaLength)) == 0);

            _Status = ::BCryptDestroyHash(_hHash);
            Assert::IsTrue(_Status >= 0);
            _Status = ::BCryptCloseAlgorithmProvider(_hAlg, 0);
            Assert::IsTrue(_Status >= 0);
        }

        TEST_METHOD(MD5)
        {
            static const byte kTargetSha[16] = { 0x20, 0x2c, 0xb9, 0x62, 0xac, 0x59, 0x07, 0x5b, 0x96, 0x4b, 0x07, 0x15, 0x2d, 0x23, 0x4b, 0x70 };

            TestHash(BCRYPT_MD5_ALGORITHM, 0, kTargetSha);
        }

        TEST_METHOD(Sha1)
        {
            static const byte kTargetSha[20] = { 0x40, 0xbd, 0x00, 0x15, 0x63, 0x08, 0x5f, 0xc3, 0x51, 0x65, 0x32, 0x9e, 0xa1, 0xff, 0x5c, 0x5e, 0xcb, 0xdb, 0xbe, 0xef };

            TestHash(BCRYPT_SHA1_ALGORITHM, 0, kTargetSha);
        }

        TEST_METHOD(Sha256)
        {
            static const byte kTargetSha[32] = { 0xa6, 0x65, 0xa4, 0x59, 0x20, 0x42, 0x2f, 0x9d, 0x41, 0x7e, 0x48, 0x67, 0xef, 0xdc, 0x4f, 0xb8, 0xa0, 0x4a, 0x1f, 0x3f, 0xff, 0x1f, 0xa0, 0x7e, 0x99, 0x8e, 0x86, 0xf7, 0xf7, 0xa2, 0x7a, 0xe3 };

            TestHash(BCRYPT_SHA256_ALGORITHM, 0, kTargetSha);
        }

        TEST_METHOD(HMAC_Sha1)
        {
            struct TestInfo
            {
                const char* pKey;
                byte TargetSha1[20];
            };

            static const TestInfo s_Info[] =
            {
                {"", { 0x65, 0x8a, 0x09, 0x01, 0x62, 0x35, 0x68, 0xea, 0x5c, 0x36, 0x31, 0xcf, 0x61, 0x93, 0xa0, 0x23, 0xd6, 0x57, 0xae, 0x4f }},
                {"1", { 0x9e, 0x72, 0xd6, 0x6a, 0x7e, 0xe6, 0xf0, 0x1a, 0xbd, 0x7e, 0xd7, 0x6c, 0xcf, 0x94, 0xfb, 0x3e, 0x70, 0xf4, 0x0e, 0x45 }},
                {"456", { 0xc9, 0x4a, 0x24, 0x9b, 0x57, 0xc0, 0x62, 0xba, 0x17, 0x5d, 0xb6, 0x43, 0x41, 0x24, 0x22, 0xe8, 0xc3, 0x91, 0x63, 0x54 }},
            };

            for (auto& _Item : s_Info)
            {
                TestHash(BCRYPT_SHA1_ALGORITHM, BCRYPT_ALG_HANDLE_HMAC_FLAG, _Item.TargetSha1, _Item.pKey);
            }
        }
    };
}
