import { getPackagingFee } from "./plugin";

export function getConfig() {
  return {
    additionalFees: [
      {
        code: "packaging-fee",
        name: "Packaging Fee",
        price: getPackagingFee(),
        taxDetails: {
          taxable: true,
        },
      },
    ],
  };
}
