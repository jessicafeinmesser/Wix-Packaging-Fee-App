// src/event-handlers-modules.ts

// src/service-plugins.ts
function ServicePluginDefinition(componentType, methods) {
  return {
    __type: "service-plugin-definition",
    componentType,
    methods
  };
}

function transformRESTFloatToSDKFloat(val) {
    if (val === 'NaN') {
        return NaN;
    }
    if (val === 'Infinity') {
        return Infinity;
    }
    if (val === '-Infinity') {
        return -Infinity;
    }
    return val;
}

function transformPath(obj, { path, isRepeated, isMap, }, transformFn) {
    const pathParts = path.split('.');
    if (pathParts.length === 1 && path in obj) {
        obj[path] = isRepeated
            ? obj[path].map(transformFn)
            : isMap
                ? Object.fromEntries(Object.entries(obj[path]).map(([key, value]) => [key, transformFn(value)]))
                : transformFn(obj[path]);
        return obj;
    }
    const [first, ...rest] = pathParts;
    if (first.endsWith('{}')) {
        const cleanPath = first.slice(0, -2);
        obj[cleanPath] = Object.fromEntries(Object.entries(obj[cleanPath]).map(([key, value]) => [
            key,
            transformPath(value, { path: rest.join('.'), isRepeated, isMap }, transformFn),
        ]));
    }
    else if (Array.isArray(obj[first])) {
        obj[first] = obj[first].map((item) => transformPath(item, { path: rest.join('.'), isRepeated, isMap }, transformFn));
    }
    else if (first in obj &&
        typeof obj[first] === 'object' &&
        obj[first] !== null) {
        obj[first] = transformPath(obj[first], { path: rest.join('.'), isRepeated, isMap }, transformFn);
    }
    return obj;
}
function transformPaths(obj, transformations) {
    return transformations.reduce((acc, { paths, transformFn }) => paths.reduce((transformerAcc, path) => transformPath(transformerAcc, path, transformFn), acc), obj);
}

const SDKRequestToRESTRequestRenameMap = {
    _id: 'id',
    _createdDate: 'createdDate',
    _updatedDate: 'updatedDate',
};
const RESTResponseToSDKResponseRenameMap = {
    id: '_id',
    createdDate: '_createdDate',
    updatedDate: '_updatedDate',
};

/**
 * Recursively rename nested keys provided in `renameMap` in the given object.
 * Providing a list of paths to ignore will prevent renaming of keys in nested objects.
 *
 * Paths are provided in the format of 'path.to.nested.field'
 * @param payload The object to rename keys for
 * @param renameMap A map of keys to rename, where the key is the original key and the value is the new key
 * @param ignorePaths Paths of nested fields to ignore while traversing the object
 * @returns The object with renamed keys
 */
function renameAllNestedKeys(payload, renameMap, ignorePaths) {
    const isIgnored = (path) => ignorePaths.includes(path);
    const traverse = (obj, path) => {
        if (Array.isArray(obj)) {
            obj.forEach((item) => {
                traverse(item, path);
            });
        }
        else if (typeof obj === 'object' && obj !== null) {
            const objAsRecord = obj;
            Object.keys(objAsRecord).forEach((key) => {
                const newPath = path === '' ? key : `${path}.${key}`;
                if (isIgnored(newPath)) {
                    return;
                }
                if (key in renameMap && !(renameMap[key] in objAsRecord)) {
                    objAsRecord[renameMap[key]] = objAsRecord[key];
                    // eslint-disable-next-line @typescript-eslint/no-dynamic-delete
                    delete objAsRecord[key];
                }
                traverse(objAsRecord[key], newPath);
            });
        }
    };
    traverse(payload, '');
    return payload;
}
function renameKeysFromSDKRequestToRESTRequest(payload, ignorePaths = []) {
    return renameAllNestedKeys(payload, SDKRequestToRESTRequestRenameMap, ignorePaths);
}
function renameKeysFromRESTResponseToSDKResponse(payload, ignorePaths = []) {
    return renameAllNestedKeys(payload, RESTResponseToSDKResponseRenameMap, ignorePaths);
}

// src/index.ts
var wixContext = {};

function resolveContext() {
    const oldContext = typeof $wixContext !== 'undefined' && $wixContext.initWixModules
        ? $wixContext.initWixModules
        : typeof globalThis.__wix_context__ !== 'undefined' &&
            globalThis.__wix_context__.initWixModules
            ? globalThis.__wix_context__.initWixModules
            : undefined;
    if (oldContext) {
        return {
            // @ts-expect-error
            initWixModules(modules, elevated) {
                return runWithoutContext(() => oldContext(modules, elevated));
            },
            fetchWithAuth() {
                throw new Error('fetchWithAuth is not available in this context');
            },
            graphql() {
                throw new Error('graphql is not available in this context');
            },
        };
    }
    const contextualClient = typeof $wixContext !== 'undefined'
        ? $wixContext.client
        : typeof wixContext.client !== 'undefined'
            ? wixContext.client
            : typeof globalThis.__wix_context__ !== 'undefined'
                ? globalThis.__wix_context__.client
                : undefined;
    const elevatedClient = typeof $wixContext !== 'undefined'
        ? $wixContext.elevatedClient
        : typeof wixContext.elevatedClient !== 'undefined'
            ? wixContext.elevatedClient
            : typeof globalThis.__wix_context__ !== 'undefined'
                ? globalThis.__wix_context__.elevatedClient
                : undefined;
    if (!contextualClient && !elevatedClient) {
        return;
    }
    return {
        initWixModules(wixModules, elevated) {
            if (elevated) {
                if (!elevatedClient) {
                    throw new Error('An elevated client is required to use elevated modules. Make sure to initialize the Wix context with an elevated client before using elevated SDK modules');
                }
                return runWithoutContext(() => elevatedClient.use(wixModules));
            }
            if (!contextualClient) {
                throw new Error('Wix context is not available. Make sure to initialize the Wix context before using SDK modules');
            }
            return runWithoutContext(() => contextualClient.use(wixModules));
        },
        fetchWithAuth: (urlOrRequest, requestInit) => {
            if (!contextualClient) {
                throw new Error('Wix context is not available. Make sure to initialize the Wix context before using SDK modules');
            }
            return contextualClient.fetchWithAuth(urlOrRequest, requestInit);
        },
        async graphql(query, variables, opts) {
            if (!contextualClient) {
                throw new Error('Wix context is not available. Make sure to initialize the Wix context before using SDK modules');
            }
            return contextualClient.graphql(query, variables, opts);
        },
    };
}
function runWithoutContext(fn) {
    const globalContext = globalThis.__wix_context__;
    const moduleContext = {
        client: wixContext.client,
        elevatedClient: wixContext.elevatedClient,
    };
    let closureContext;
    globalThis.__wix_context__ = undefined;
    wixContext.client = undefined;
    wixContext.elevatedClient = undefined;
    if (typeof $wixContext !== 'undefined') {
        closureContext = {
            client: $wixContext?.client,
            elevatedClient: $wixContext?.elevatedClient,
        };
        delete $wixContext.client;
        delete $wixContext.elevatedClient;
    }
    try {
        return fn();
    }
    finally {
        globalThis.__wix_context__ = globalContext;
        wixContext.client = moduleContext.client;
        wixContext.elevatedClient = moduleContext.elevatedClient;
        if (typeof $wixContext !== 'undefined') {
            $wixContext.client = closureContext.client;
            $wixContext.elevatedClient = closureContext.elevatedClient;
        }
    }
}

function contextualizeRESTModuleV2(restModule, elevated) {
    return ((...args) => {
        const context = resolveContext();
        if (!context) {
            // @ts-expect-error - if there is no context, we want to behave like the original module
            return restModule.apply(undefined, args);
        }
        return (context
            .initWixModules(restModule, elevated)
            // @ts-expect-error - we know the args here are meant to be passed to the initalized module
            .apply(undefined, args));
    });
}
function contextualizeSerivcePluginModuleV2(servicePlugin) {
    const contextualMethod = ((...args) => {
        const context = resolveContext();
        if (!context) {
            // this line should throw, but this would be a breaking change for older SDK versions
            // this is because in wixClient there's code that calls any function it detects and checks
            // if it's an ambassador module (see isAmbassadorModule)
            return () => { };
        }
        return context.initWixModules(servicePlugin).apply(undefined, args);
    });
    contextualMethod.__type = servicePlugin.__type;
    contextualMethod.componentType = servicePlugin.componentType;
    contextualMethod.methods = servicePlugin.methods;
    return contextualMethod;
}

function createServicePluginModule(servicePluginDefinition) {
    return contextualizeSerivcePluginModuleV2(servicePluginDefinition);
}

function removeUndefinedKeys(obj) {
    return Object.fromEntries(Object.entries(obj).filter(([, value]) => value !== undefined));
}

function transformRESTAddressToSDKAddress(payload) {
    return (payload &&
        removeUndefinedKeys({
            formatted: payload.formattedAddress,
            location: payload.geocode,
            addressLine1: payload.addressLine,
            addressLine2: payload.addressLine2,
            streetAddress: payload.streetAddress && {
                name: payload.streetAddress.name,
                number: payload.streetAddress.number,
                apt: payload.streetAddress.apt,
            },
            city: payload.city,
            subdivision: payload.subdivision,
            country: payload.country,
            postalCode: payload.postalCode,
            countryFullname: payload.countryFullname,
            subdivisionFullname: payload.subdivisionFullname,
        }));
}

const provideHandlers$1 = ServicePluginDefinition('ECOM_ADDITIONAL_FEES', [
    {
        name: 'calculateAdditionalFees',
        primaryHttpMappingPath: '/v1/calculate-additional-fees',
        transformations: {
            toREST: (payload) => {
                const toRestResponse = payload;
                return renameKeysFromSDKRequestToRESTRequest(toRestResponse);
            },
            fromREST: (payload) => {
                const fromRestRequest = transformPaths(payload, [
                    {
                        transformFn: transformRESTAddressToSDKAddress,
                        paths: [
                            { path: 'request.shippingAddress' },
                            {
                                path: 'request.shippingInfo.selectedCarrierServiceOption.logistics.pickupDetails.address',
                            },
                        ],
                    },
                    {
                        transformFn: transformRESTFloatToSDKFloat,
                        paths: [{ path: 'request.lineItems.physicalProperties.weight' }],
                    },
                ]);
                return renameKeysFromRESTResponseToSDKResponse(fromRestRequest);
            },
        },
    },
]);

const provideHandlers = createServicePluginModule(provideHandlers$1);

function createRESTModule(descriptor, elevated = false) {
    return contextualizeRESTModuleV2(descriptor, elevated);
}

const fetchWithAuth = createRESTModule((restModuleOpts) => {
    return ((url, options) => restModuleOpts.fetchWithAuth(url, options));
});

console.log("🚀 Plugin is starting...");
async function getPackagingFee() {
  try {
    const response = await fetchWithAuth(
      `${undefined                            }/packaging-fee-api`
      //VITE_?
    );
    if (!response.ok) throw new Error("Failed to fetch packaging fee");
    const data = await response.json();
    console.log("received packaging fee of ", data.fee);
    return parseFloat(data.fee);
  } catch (error) {
    console.error("Error fetching packaging fee:", error);
    return 10;
  }
}
provideHandlers({
  calculateAdditionalFees: async ({ metadata }) => {
    const currency = metadata?.currency || "ILS";
    const packagingFee = await getPackagingFee();
    console.log(`Applying packaging fee: ${packagingFee} ${currency}`);
    return {
      additionalFees: [
        {
          code: "packaging-fee",
          name: "Packaging Fee",
          price: packagingFee.toString(),
          taxDetails: {
            taxable: true
          }
        }
      ],
      currency
    };
  }
});

export { getPackagingFee };
//# sourceMappingURL=plugin.mjs.map
