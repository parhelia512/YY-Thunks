#include <bcrypt.h>
#include <wincrypt.h>

#if (YY_Thunks_Support_Version < NTDDI_WIN6)
#pragma comment(lib, "Advapi32.lib")
#endif

namespace YY
{
	namespace Thunks
	{
		

#ifdef YY_Thunks_Implemented
        struct BCryptHash;
        struct BCryptAlgorithm;
        struct BCryptMapItem;
        typedef NTSTATUS(__fastcall* OpenAlgorithmProviderType)(
            _In_     const BCryptMapItem* _pCryptMapItem,
            _In_     ULONG              _fFlags,
            _Outptr_ BCryptAlgorithm** _ppAlgorithm);

		struct BCryptMapItem
		{
			LPCWSTR szProvider;
            LPCWSTR szAlgName;
            DWORD cbAlgId;
			DWORD uProvType;
			DWORD uAlgId;
            OpenAlgorithmProviderType pfnOpenAlgorithmProviderType;

            template<DWORD _cchAlgId>
            constexpr BCryptMapItem(const wchar_t (&_szAlgName)[_cchAlgId], LPCWSTR _szProvider, DWORD _uProvType, DWORD _uAlgId, OpenAlgorithmProviderType _pOpenAlgorithmProvider)
                : szProvider(_szProvider)
                , szAlgName(_szAlgName)
                , cbAlgId(sizeof(_szAlgName))
                , uProvType(_uProvType)
                , uAlgId(_uAlgId)
                , pfnOpenAlgorithmProviderType(_pOpenAlgorithmProvider)
            {
            }
		};

        class BCryptObject
        {
            static constexpr auto kBCryptObjectMagic = 0x998u;

            DWORD uMagic = kBCryptObjectMagic;
            ULONG uRef = 1u;

        public:
            DWORD uAlgId = 0;
            bool bCanFree = true;

            BCryptObject(DWORD _uAlgId)
                : uAlgId(_uAlgId)
            {
            }

            virtual ~BCryptObject()
            {
                // 故意修改，便于 IsBCrypyAlgHandle 时判断有效性。
                uMagic = 0;
            }

            bool IsValid() const
            {
                return uMagic == kBCryptObjectMagic;
            }

            DWORD GetClass() const
            {
                return GET_ALG_CLASS(uAlgId);
            }

            bool IsHash()
            {
                return GetClass() == ALG_CLASS_HASH;
            }

            void AddRef()
            {
                InterlockedIncrement(&uRef);
            }

            void Release()
            {
                if (InterlockedDecrement(&uRef) == 0)
                {
                    this->~BCryptObject();
                    if (bCanFree)
                    {
                        const auto _hProcessHeap = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessHeap;
                        HeapFree(_hProcessHeap, 0, this);
                    }
                }
            }

            virtual NTSTATUS WINAPI GetProperty(
                _In_z_                                      LPCWSTR pszProperty,
                _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
                _In_                                        ULONG   cbOutput,
                _Out_                                       ULONG* pcbResult,
                _In_                                        ULONG   dwFlags
                ) = 0;
        };

        struct BCryptAlgorithm : public BCryptObject
        {
            const BCryptMapItem* pMapItem = nullptr;
            ULONG fOpenAlgorithmFlags = 0;

            BCryptAlgorithm()
                : BCryptObject(0)
            {
            }

            bool IsRng() const
            {
                return pMapItem->uAlgId == 0;
            }

            bool CanCreateHash() const
            {
                return GET_ALG_CLASS(pMapItem->uAlgId) == ALG_CLASS_HASH;
            }

            DWORD __fastcall GetHashLength() const
            {
                constexpr auto kByteBits = 32 / sizeof(UINT32);

                switch (pMapItem->uAlgId)
                {
                case CALG_MD2:
                    return 32 / kByteBits;
                    break;
                case CALG_MD4:
                    return 128 / kByteBits;
                    break;
                case CALG_MD5:
                    return 128 / kByteBits;
                    break;
                case CALG_SHA1:
                    return 160 / kByteBits;
                    break;
                case CALG_SHA_256:
                    return 256 / kByteBits;
                    break;
                case CALG_SHA_384:
                    return 384 / kByteBits;
                    break;
                case CALG_SHA_512:
                    return 512 / kByteBits;
                    break;
                default:
                    return 0;
                    break;
                }
            }
            
            NTSTATUS WINAPI GetProperty(
                _In_z_                                      LPCWSTR pszProperty,
                _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
                _In_                                        ULONG   cbOutput,
                _Out_                                       ULONG* pcbResult,
                _In_                                        ULONG   dwFlags
                ) override
            {
                if (__wcsnicmp_ascii(BCRYPT_ALGORITHM_NAME, pszProperty, -1) == 0)
                {
                    *pcbResult = pMapItem->cbAlgId;
                    if (!pbOutput)
                    {
                        return STATUS_SUCCESS;
                    }

                    if (cbOutput < pMapItem->cbAlgId)
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    memcpy(pbOutput, pMapItem->szAlgName, pMapItem->cbAlgId);
                    return STATUS_SUCCESS;
                }
                else if (__wcsnicmp_ascii(BCRYPT_PROVIDER_HANDLE, pszProperty, -1) == 0)
                {
                    *pcbResult = sizeof(BCRYPT_ALG_HANDLE);
                    if (!pbOutput)
                    {
                        return STATUS_SUCCESS;
                    }

                    if (cbOutput < sizeof(BCRYPT_ALG_HANDLE))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    *reinterpret_cast<BCRYPT_ALG_HANDLE*>(pcbResult) = this;
                    return STATUS_SUCCESS;
                }

                return STATUS_NOT_SUPPORTED;
            }

            virtual
            NTSTATUS
            WINAPI
            CreateHash(
                _Outptr_                                 BCryptHash** ppHash,
                _Out_writes_bytes_all_opt_(cbHashObject) PUCHAR   pbHashObject,
                _In_                                     ULONG   cbHashObject,
                _In_reads_bytes_opt_(cbSecret)           PUCHAR   pbSecret,   // optional
                _In_                                     ULONG   cbSecret,   // optional
                _In_                                     ULONG   dwFlags)
            {
                return STATUS_NOT_SUPPORTED;
            }
        };

        struct BCryptAlgorithmByCryptoAPI : BCryptAlgorithm
        {
            HCRYPTPROV hProv = NULL;

            ~BCryptAlgorithmByCryptoAPI()
            {
                if (hProv)
                    CryptReleaseContext(hProv, 0);
            }

            template<typename BCryptAlgorithmT>
            static NTSTATUS __fastcall Create(_In_ const BCryptMapItem* _pMapItem, _In_ ULONG _fOpenAlgorithmFlags, _Outptr_ BCryptAlgorithm** _ppAlgorithm)
            {
                *_ppAlgorithm = nullptr;

                HCRYPTPROV _hProv;
                if (!CryptAcquireContextW(&_hProv, nullptr, _pMapItem->szProvider, _pMapItem->uProvType, CRYPT_VERIFYCONTEXT))
                    return STATUS_INVALID_PARAMETER;

                const auto _hProcessHeap = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessHeap;
                auto _pBCryptAlgorithm = (BCryptAlgorithmT*)HeapAlloc(_hProcessHeap, 0, sizeof(BCryptAlgorithmT));
                if (!_pBCryptAlgorithm)
                {
                    CryptReleaseContext(_hProv, 0);
                    return STATUS_NO_MEMORY;
                }

                new (_pBCryptAlgorithm) BCryptAlgorithmT();
                _pBCryptAlgorithm->pMapItem = _pMapItem;
                _pBCryptAlgorithm->hProv = _hProv;
                _pBCryptAlgorithm->fOpenAlgorithmFlags = _fOpenAlgorithmFlags;
                *_ppAlgorithm = _pBCryptAlgorithm;
                return STATUS_SUCCESS;
            }
        };

        struct BCryptHash : public BCryptObject
        {
            BCryptAlgorithmByCryptoAPI* pAlgorithm = nullptr;
            ULONG dwFlags = 0;
            HCRYPTKEY hPubKey = NULL;
            HCRYPTHASH hHash = NULL;

            BCryptHash(_In_ BCryptAlgorithmByCryptoAPI* _pAlgorithm)
                : BCryptObject(_pAlgorithm->pMapItem->uAlgId)
                , pAlgorithm(_pAlgorithm)
            {
                pAlgorithm->AddRef();
            }

            ~BCryptHash()
            {
                if(hPubKey)
                    CryptDestroyKey(hPubKey);

                if(hHash)
                    CryptDestroyHash(hHash);

                if (pAlgorithm)
                    pAlgorithm->Release();
            }

            NTSTATUS WINAPI Init(
                _In_reads_bytes_opt_(_cbSecret) PUCHAR _pbSecret,   // optional
                _In_                            ULONG  _cbSecret,   // optional
                _In_                            ULONG  _dwFlags)
            {
                if (pAlgorithm->fOpenAlgorithmFlags & BCRYPT_ALG_HANDLE_HMAC_FLAG)
                {
                    // https://learn.microsoft.com/zh-cn/windows/win32/seccrypto/example-c-program--importing-a-plaintext-key
                    struct _PLAINTEXTKEYBLOB : public BLOBHEADER
                    {
                        DWORD dwKeySize;
                        BYTE rgbKeyData[2];
                    };

                    const auto _cbKeyBlob = sizeof(_PLAINTEXTKEYBLOB) + _cbSecret;
                    auto _pKeyBlob = static_cast<_PLAINTEXTKEYBLOB*>(_malloca(_cbKeyBlob));
                    if (!_pKeyBlob)
                    {
                        return STATUS_NO_MEMORY;
                    }
                    _pKeyBlob->bType = PLAINTEXTKEYBLOB;
                    _pKeyBlob->bVersion = CUR_BLOB_VERSION;
                    _pKeyBlob->reserved = 0;
                    _pKeyBlob->aiKeyAlg = CALG_RC2;
                    memcpy(_pKeyBlob->rgbKeyData, _pbSecret, _cbSecret);
                    if (_cbSecret >= 2)
                    {
                        _pKeyBlob->dwKeySize = _cbSecret;
                    }
                    else
                    {
                        // 长度小于 2字节时 CryptImportKey 会失败，特殊处理一下
                        _pKeyBlob->dwKeySize = 2;
                        if (_cbSecret == 0)
                        {
                            _pKeyBlob->rgbKeyData[0] = 0;
                        }
                        _pKeyBlob->rgbKeyData[1] = 0;
                    }

                    auto _bResult = CryptImportKey(pAlgorithm->hProv, reinterpret_cast<BYTE*>(_pKeyBlob), _cbKeyBlob, NULL, CRYPT_IPSEC_HMAC_KEY, &hPubKey);
                    // 避免密钥泄漏，所以立即将内存值清空！！！
                    memset(_pKeyBlob, 0, _cbKeyBlob);
                    _freea(_pKeyBlob);

                    if (!_bResult)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    if (!CryptCreateHash(pAlgorithm->hProv, CALG_HMAC, hPubKey, 0, &hHash))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }

                    HMAC_INFO _HMacInfo = { pAlgorithm->pMapItem->uAlgId };
                    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, reinterpret_cast<BYTE*>(&_HMacInfo), 0))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }
                else
                {
                    if (!CryptCreateHash(pAlgorithm->hProv, pAlgorithm->pMapItem->uAlgId, NULL, 0, &hHash))
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                }

                dwFlags = _dwFlags;
                return STATUS_SUCCESS;
            }

            NTSTATUS
            WINAPI
            HashData(
                _In_reads_bytes_(cbInput)    PUCHAR   pbInput,
                _In_                    ULONG   cbInput,
                _In_                    ULONG   dwFlags)
            {
                if (!CryptHashData(hHash, pbInput, cbInput, 0))
                    return STATUS_INVALID_PARAMETER;
                return STATUS_SUCCESS;
            }

            NTSTATUS
            WINAPI
            FinishHash(
                _Out_writes_bytes_all_(cbOutput) PUCHAR   pbOutput,
                _In_                        ULONG   cbOutput,
                _In_                        ULONG   dwFlags)
            {
                const auto _cbTargetHashLength = pAlgorithm->GetHashLength();
                if (cbOutput < _cbTargetHashLength)
                {
                    return STATUS_BUFFER_TOO_SMALL;
                }
                else if (cbOutput != _cbTargetHashLength)
                {
                    return STATUS_INVALID_PARAMETER;
                }

                STATUS_INVALID_PARAMETER;
                if (!CryptGetHashParam(hHash, HP_HASHVAL, pbOutput, &cbOutput, 0))
                    return STATUS_INVALID_PARAMETER;

                return STATUS_SUCCESS;
            }

            NTSTATUS WINAPI GetProperty(
                _In_z_                                      LPCWSTR pszProperty,
                _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
                _In_                                        ULONG   cbOutput,
                _Out_                                       ULONG* pcbResult,
                _In_                                        ULONG   dwFlags
                ) override
            {
                return pAlgorithm->GetProperty(pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
            }
        };

        struct BCryptAlgorithmHash : public BCryptAlgorithmByCryptoAPI
        {
            NTSTATUS WINAPI GetProperty(
                _In_z_                                      LPCWSTR pszProperty,
                _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
                _In_                                        ULONG   cbOutput,
                _Out_                                       ULONG* pcbResult,
                _In_                                        ULONG   dwFlags
                ) override
            {
                if (__wcsnicmp_ascii(BCRYPT_OBJECT_LENGTH, pszProperty, -1) == 0)
                {
                    *pcbResult = sizeof(BCryptHash);
                    if (!pbOutput)
                    {
                        return STATUS_SUCCESS;
                    }

                    if (cbOutput < sizeof(BCryptHash))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    *reinterpret_cast<DWORD*>(pbOutput) = sizeof(BCryptHash);
                    return STATUS_SUCCESS;
                }
                else if (__wcsnicmp_ascii(BCRYPT_HASH_LENGTH, pszProperty, -1) == 0)
                {
                    *pcbResult = sizeof(DWORD);
                    if (!pbOutput)
                    {
                        return STATUS_SUCCESS;
                    }

                    if (cbOutput < sizeof(DWORD))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    *reinterpret_cast<DWORD*>(pbOutput) = GetHashLength();
                    return STATUS_SUCCESS;
                }

                return BCryptAlgorithm::GetProperty(pszProperty, pbOutput, cbOutput, pcbResult, dwFlags); 
            }


            NTSTATUS
            WINAPI
            CreateHash(
                _Outptr_                                 BCryptHash** ppHash,
                _Out_writes_bytes_all_opt_(cbHashObject) PUCHAR   pbHashObject,
                _In_                                     ULONG   cbHashObject,
                _In_reads_bytes_opt_(cbSecret)           PUCHAR   pbSecret,   // optional
                _In_                                     ULONG   cbSecret,   // optional
                _In_                                     ULONG   dwFlags)
            {
                BCryptHash* _pBCryptHash = reinterpret_cast<BCryptHash*>(pbHashObject);
                if (_pBCryptHash)
                {
                    if (cbHashObject < sizeof(BCryptHash))
                    {
                        return STATUS_BUFFER_TOO_SMALL;
                    }

                    new (_pBCryptHash) BCryptHash(this);
                    _pBCryptHash->bCanFree = false;
                }
                else
                {
                    if (cbHashObject != 0)
                    {
                        return STATUS_INVALID_PARAMETER;
                    }
                    const auto _hProcessHeap = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessHeap;
                    _pBCryptHash = (BCryptHash*)HeapAlloc(_hProcessHeap, 0, sizeof(BCryptHash));
                    if (!_pBCryptHash)
                    {
                        return STATUS_NO_MEMORY;
                    }

                    new (_pBCryptHash) BCryptHash(this);
                }

                auto _Status = _pBCryptHash->Init(pbSecret, cbSecret, dwFlags);
                if (_Status)
                {
                    _pBCryptHash->Release();
                    return _Status;
                }
                *ppHash = _pBCryptHash;
                return STATUS_SUCCESS;
            }
        };

        struct BCryptAlgorithmRng : public BCryptAlgorithm
        {
            static NTSTATUS __fastcall Create(_In_ const BCryptMapItem* _pMapItem, _In_ ULONG _fOpenAlgorithmFlags, _Outptr_ BCryptAlgorithm** _ppAlgorithm)
            {
                *_ppAlgorithm = nullptr;

                const auto _hProcessHeap = ((TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessHeap;
                auto _pBCryptAlgorithm = (BCryptAlgorithmRng*)HeapAlloc(_hProcessHeap, 0, sizeof(BCryptAlgorithmRng));
                if (!_pBCryptAlgorithm)
                {
                    return STATUS_NO_MEMORY;
                }

                new (_pBCryptAlgorithm) BCryptAlgorithmRng();
                _pBCryptAlgorithm->pMapItem = _pMapItem;
                _pBCryptAlgorithm->fOpenAlgorithmFlags = _fOpenAlgorithmFlags;
                *_ppAlgorithm = _pBCryptAlgorithm;
                return STATUS_SUCCESS;
            }
        };


        template<typename TargrtObject>
        bool __fastcall Is(void* _pSrc);

        template<>
        bool __fastcall Is<BCryptObject>(void* _pSrc)
        {
            auto _BCryptObject = reinterpret_cast<BCryptObject*>(_pSrc);
            return _BCryptObject != nullptr && _BCryptObject->IsValid();
        }

        template<>
        bool __fastcall Is<BCryptAlgorithm>(void* _pSrc)
        {
            if (!Is<BCryptObject>(_pSrc))
                return false;

            return reinterpret_cast<BCryptObject*>(_pSrc)->GetClass() == 0;
        }

        template<>
        bool __fastcall Is<BCryptAlgorithmRng>(void* _pSrc)
        {
            if (!Is<BCryptAlgorithm>(_pSrc))
                return false;

            return reinterpret_cast<BCryptAlgorithmRng*>(_pSrc)->IsRng();
        }

        template<>
        bool __fastcall Is<BCryptHash>(void* _pSrc)
        {
            if (!Is<BCryptObject>(_pSrc))
                return false;

            return reinterpret_cast<BCryptObject*>(_pSrc)->IsHash();
        }
#endif

#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		16,
		NTSTATUS,
		WINAPI,
		BCryptOpenAlgorithmProvider,
			_Out_       BCRYPT_ALG_HANDLE* _phAlgorithm,
			_In_        LPCWSTR            _szAlgId,
			_In_opt_    LPCWSTR            _szImplementation,
			_In_        ULONG              _fFlags
			)
		{
			if (const auto _pfnBCryptOpenAlgorithmProvider = try_get_BCryptOpenAlgorithmProvider())
			{
				return _pfnBCryptOpenAlgorithmProvider(_phAlgorithm, _szAlgId, _szImplementation, _fFlags);
			}

			UNREFERENCED_PARAMETER(_szImplementation);

            static const BCryptMapItem g_Map[] =
            {
                // 加密算法
                // { L"AES", MS_ENH_RSA_AES_PROV_XP_W, PROV_RSA_AES, CALG_AES },
                // { L"DES", MS_DEF_DSS_PROV_W, PROV_DSS, CALG_DES },
                // { L"RC2", MS_ENH_RSA_AES_PROV_XP_W, PROV_RSA_AES, CALG_RC2 },
                // { L"RC4", MS_ENH_RSA_AES_PROV_XP_W, PROV_RSA_AES, CALG_RC4 },

                // 生成随机数算法
                { BCRYPT_RNG_ALGORITHM, nullptr, 0, 0, &BCryptAlgorithmRng::Create },
                { BCRYPT_RNG_FIPS186_DSA_ALGORITHM, nullptr, 0, 0, &BCryptAlgorithmRng::Create },
                { BCRYPT_RNG_DUAL_EC_ALGORITHM, nullptr, 0, 0, &BCryptAlgorithmRng::Create },

                // Hash算法
                { L"MD2", nullptr, PROV_RSA_AES, CALG_MD2, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"MD4", nullptr, PROV_RSA_AES, CALG_MD4, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"MD5", nullptr, PROV_RSA_AES, CALG_MD5, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"SHA1", nullptr, PROV_RSA_AES, CALG_SHA1, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"SHA256", nullptr, PROV_RSA_AES, CALG_SHA_256, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"SHA384", nullptr, PROV_RSA_AES, CALG_SHA_384, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
                { L"SHA512", nullptr, PROV_RSA_AES, CALG_SHA_512, &BCryptAlgorithmByCryptoAPI::Create<BCryptAlgorithmHash> },
            };

            for (auto& _Item : g_Map)
            {
                if (__wcsnicmp_ascii(_szAlgId, _Item.szAlgName, (size_t)-1) == 0)
                {
                    return _Item.pfnOpenAlgorithmProviderType(&_Item, _fFlags, reinterpret_cast<BCryptAlgorithm**>(_phAlgorithm));
                }
            }

            return STATUS_NOT_FOUND;
		}
#endif

#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		8,
		NTSTATUS,
		WINAPI,
		BCryptCloseAlgorithmProvider,
			_Inout_ BCRYPT_ALG_HANDLE _hAlgorithm,
			_In_    ULONG _fFlags)
		{
			if (auto _pfnBCryptCloseAlgorithmProvider = try_get_BCryptCloseAlgorithmProvider())
			{
				return _pfnBCryptCloseAlgorithmProvider(_hAlgorithm, _fFlags);
			}

			UNREFERENCED_PARAMETER(_fFlags);

            if (!Is<BCryptAlgorithm>(_hAlgorithm))
                return STATUS_INVALID_PARAMETER;

            reinterpret_cast<BCryptObject*>(_hAlgorithm)->Release();
            return STATUS_SUCCESS;
		}
#endif

#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		16,
		NTSTATUS,
		WINAPI,
		BCryptGenRandom,
			_In_opt_                        BCRYPT_ALG_HANDLE _hAlgorithm,
			_Out_writes_bytes_(_cbBuffer)   PUCHAR _pbBuffer,
			_In_                            ULONG _cbBuffer,
			_In_                            ULONG _fFlags
			)
		{
			if (auto _pfnBCryptGenRandom = try_get_BCryptGenRandom())
			{
				return _pfnBCryptGenRandom(_hAlgorithm, _pbBuffer, _cbBuffer, _fFlags);
			}
			
			if (_pbBuffer == nullptr)
				return STATUS_INVALID_PARAMETER;
			if (_cbBuffer == 0)
				return STATUS_SUCCESS;

			if (_fFlags & BCRYPT_USE_SYSTEM_PREFERRED_RNG)
			{
				if(_hAlgorithm != NULL)
					return STATUS_INVALID_PARAMETER;
			}
			else
			{
                if (!Is<BCryptAlgorithmRng>(_hAlgorithm))
                {
                    return STATUS_INVALID_HANDLE;
                }
			}

			// 此函数内部其实就是用了Crypt API，所以针对Windows XP就直接使用它了。
			const auto _pfnRtlGenRandom = try_get_SystemFunction036();
			if (!_pfnRtlGenRandom)
			{
				internal::RaiseStatus(STATUS_NOT_IMPLEMENTED);
				return STATUS_NOT_IMPLEMENTED;
			}
			
			if (_pfnRtlGenRandom(_pbBuffer, _cbBuffer))
				return STATUS_SUCCESS;
			else
				return STATUS_UNSUCCESSFUL;
		}
#endif


#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		24,
		NTSTATUS,
        WINAPI,
        BCryptGetProperty,
            _In_                                        BCRYPT_HANDLE   hObject,
            _In_z_                                      LPCWSTR pszProperty,
            _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR   pbOutput,
            _In_                                        ULONG   cbOutput,
            _Out_                                       ULONG   *pcbResult,
            _In_                                        ULONG   dwFlags
            )
		{
			if (const auto _pfnBCryptGetProperty = try_get_BCryptGetProperty())
			{
				return _pfnBCryptGetProperty(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
			}
            
            if (!Is<BCryptObject>(hObject))
            {
                return STATUS_INVALID_HANDLE;
            }
            
            return reinterpret_cast<BCryptObject*>(hObject)->GetProperty(pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
		}
#endif


#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		28,
		NTSTATUS,
        WINAPI,
        BCryptCreateHash,
            _Inout_                             BCRYPT_ALG_HANDLE   hAlgorithm,
            _Out_                               BCRYPT_HASH_HANDLE  *phHash,
            _Out_writes_bytes_all_opt_(cbHashObject) PUCHAR   pbHashObject,
            _In_                                ULONG   cbHashObject,
            _In_reads_bytes_opt_(cbSecret)           PUCHAR   pbSecret,   // optional
            _In_                                ULONG   cbSecret,   // optional
            _In_                                ULONG   dwFlags
            )
		{
			if (const auto _pfnBCryptCreateHash = try_get_BCryptCreateHash())
			{
				return _pfnBCryptCreateHash(hAlgorithm, phHash, pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
			}

            if (!Is<BCryptAlgorithm>(hAlgorithm))
            {
                return STATUS_INVALID_HANDLE;
            }

            return reinterpret_cast<BCryptAlgorithm*>(hAlgorithm)->CreateHash(reinterpret_cast<BCryptHash**>(phHash), pbHashObject, cbHashObject, pbSecret, cbSecret, dwFlags);
		}
#endif


#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		16,
		NTSTATUS,
        WINAPI,
        BCryptHashData,
            _Inout_                 BCRYPT_HASH_HANDLE  hHash,
            _In_reads_bytes_(cbInput)    PUCHAR   pbInput,
            _In_                    ULONG   cbInput,
            _In_                    ULONG   dwFlags
            )
		{
			if (const auto _pfnBCryptHashData = try_get_BCryptHashData())
			{
				return _pfnBCryptHashData(hHash, pbInput, cbInput, dwFlags);
			}

            if (!Is<BCryptHash>(hHash))
                return STATUS_INVALID_PARAMETER;

            return reinterpret_cast<BCryptHash*>(hHash)->HashData(pbInput, cbInput, dwFlags);
		}
#endif


#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		16,
		NTSTATUS,
        WINAPI,
        BCryptFinishHash,
            _Inout_                     BCRYPT_HASH_HANDLE hHash,
            _Out_writes_bytes_all_(cbOutput) PUCHAR   pbOutput,
            _In_                        ULONG   cbOutput,
            _In_                        ULONG   dwFlags
            )
		{
			if (const auto _pfnBCryptFinishHash = try_get_BCryptFinishHash())
			{
				return _pfnBCryptFinishHash(hHash, pbOutput, cbOutput, dwFlags);
			}

            if (!Is<BCryptHash>(hHash))
                return STATUS_INVALID_PARAMETER;

            return reinterpret_cast<BCryptHash*>(hHash)->FinishHash(pbOutput, cbOutput, dwFlags);
		}
#endif


#if (YY_Thunks_Support_Version < NTDDI_WIN6)

		// 最低受支持的客户端	Windows Vista [桌面应用|UWP 应用]
		// 最低受支持的服务器	Windows Server 2008[桌面应用 | UWP 应用]
		__DEFINE_THUNK(
		bcrypt,
		4,
		NTSTATUS,
        WINAPI,
        BCryptDestroyHash,
            _Inout_ BCRYPT_HASH_HANDLE hHash)
		{
			if (const auto _pfnBCryptDestroyHash = try_get_BCryptDestroyHash())
			{
				return _pfnBCryptDestroyHash(hHash);
			}

            if (!Is<BCryptHash>(hHash))
                return STATUS_INVALID_PARAMETER;

            reinterpret_cast<BCryptHash*>(hHash)->Release();
            return STATUS_SUCCESS;
		}
#endif
	}
}
