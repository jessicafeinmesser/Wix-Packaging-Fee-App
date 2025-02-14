// import { additionalFees } from "@wix/ecom/service-plugins";
// import { httpClient, auth } from "@wix/essentials";

// console.log("🚀 Plugin is starting...");

// async function getInstanceId() {
//   try {
//     const response = await httpClient.fetchWithAuth(
//       `${import.meta.env.BASE_API_URL}/instance-id-api`
//     );

//     if (!response.ok) throw new Error("Failed to fetch instance ID");
//     const data = await response.json();
//     console.log("Received instance ID: ", data.instanceId);
//     return data.instanceId;
//   } catch (error) {
//     console.error("Error fetching instance ID:", error);
//     return null; // Return null if instance ID fetch fails
//   }
// }

// async function getPackagingFee(instanceId: any) {
//   try {
//     const response = await httpClient.fetchWithAuth(
//       `${import.meta.env.BASE_API_URL}/packaging-fee-api`,
//       {
//         headers: {
//           "X-Instance-Id": instanceId, // Include instanceId in headers
//         },
//       }
//     );

//     if (!response.ok) throw new Error("Failed to fetch packaging fee");
//     const data = await response.json();
//     console.log("Received packaging fee: ", data.fee);
//     return parseFloat(data.fee); // Default to 10 if invalid
//   } catch (error) {
//     console.error("Error fetching packaging fee:", error);
//     return 10; // Fallback value
//   }
// }

// additionalFees.provideHandlers({
//   calculateAdditionalFees: async ({ metadata }) => {
//     const currency = metadata?.currency || "ILS"; // Default to ILS if not found
//     const instanceId = await getInstanceId(); // Fetch instance ID

//     if (!instanceId) {
//       console.error("Instance ID is required for authentication.");
//       return { additionalFees: [], currency };
//     }

//     const packagingFee = await getPackagingFee(instanceId);

//     console.log(`Applying packaging fee: ${packagingFee} ${currency}`);

//     return {
//       additionalFees: [
//         {
//           code: "packaging-fee",
//           name: "Packaging Fee",
//           price: packagingFee.toString(),
//           taxDetails: {
//             taxable: true,
//           },
//         },
//       ],
//       currency: currency,
//     };
//   },
// });

// import { additionalFees } from "@wix/ecom/service-plugins";
// import { httpClient, auth } from "@wix/essentials";

// console.log("🚀 Plugin is starting...");

// export async function getPackagingFee(instanceId: string) {
//   try {
//     const response = await httpClient.fetchWithAuth(
//       `${import.meta.env.BASE_API_URL}/packaging-fee-api`,
//       {
//         headers: {
//           "X-Instance-Id": instanceId, // Include instanceId in headers
//         },
//       }
//     );

//     if (!response.ok) throw new Error("Failed to fetch packaging fee");
//     const data = await response.json();
//     console.log("Received packaging fee of ", data.fee);
//     return parseFloat(data.fee); // Default to 10 if invalid
//   } catch (error) {
//     console.error("Error fetching packaging fee:", error);
//     return 10; // Fallback value
//   }
// }

// additionalFees.provideHandlers({
//   calculateAdditionalFees: async ({ metadata }) => {
//     const currency = metadata?.currency || "ILS"; // Default to ILS if not found
//     const instanceId = metadata?.instanceId; // Ensure instanceId is available

//     if (!instanceId) {
//       console.error("Instance ID is required for authentication.");
//       return { additionalFees: [], currency };
//     }

//     const packagingFee = await getPackagingFee(instanceId);

//     console.log(`Applying packaging fee: ${packagingFee} ${currency}`);

//     return {
//       additionalFees: [
//         {
//           code: "packaging-fee",
//           name: "Packaging Fee",
//           price: packagingFee.toString(),
//           taxDetails: {
//             taxable: true,
//           },
//         },
//       ],
//       currency: currency,
//     };
//   },
// });

import { additionalFees } from "@wix/ecom/service-plugins";
import { httpClient, auth } from "@wix/essentials";
//import { createClient, ApiKeyStrategy } from "@wix/sdk";
//import dotenv from "dotenv";
//dotenv.config();

console.log("🚀 Plugin is starting...");

// const response = await httpClient.fetchWithAuth(
//   // `${import.meta.env.BASE_API_URL}/packaging-fee-api`
//   `${import.meta.env.BASE_API_URL}/packaging-fee-api` //VITE_?
// );
//console.log("current packaging fee, ", response);

// const apiKey = import.meta.env.VITE_API_KEY;
// const accountId = import.meta.env.VITE_ACCOUNT_ID;

// if (!apiKey || !accountId) {
//   throw new Error(
//     "API_KEY and ACCOUNT_ID must be defined in environment variables."
//   );
// }

// const wixClient = createClient({
//   auth: ApiKeyStrategy({
//     apiKey,
//     accountId,
//   }),
//   modules: {
//     // Include any additional modules you need
//   },
// });

export async function getPackagingFee() {
  try {
    const response = await httpClient.fetchWithAuth(
      `${import.meta.env.BASE_API_URL}/packaging-fee-api` //VITE_?
    );

    if (!response.ok) throw new Error("Failed to fetch packaging fee");
    const data = await response.json();
    console.log("received packaging fee of ", data.fee);
    return parseFloat(data.fee); // Default to 10 if invalid
  } catch (error) {
    console.error("Error fetching packaging fee:", error);
    return 10; // Fallback value
  }
}

additionalFees.provideHandlers({
  calculateAdditionalFees: async ({ metadata }) => {
    const currency = metadata?.currency || "ILS"; // Default to ILS if not found
    const packagingFee = await getPackagingFee();

    console.log(`Applying packaging fee: ${packagingFee} ${currency}`);

    return {
      additionalFees: [
        {
          code: "packaging-fee",
          name: "Packaging Fee",
          price: packagingFee.toString(),
          taxDetails: {
            taxable: true,
          },
        },
      ],
      currency: currency,
    };
  },
});
