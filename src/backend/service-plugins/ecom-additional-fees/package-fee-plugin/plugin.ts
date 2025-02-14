//plugin.ts implements the Wix Ecom Additional Fees service plugin. 
//It uses helper function  getPackagingFee to fetch the fee from the backend API and returns it in the appropriate Additional Fees format.
//It appears that it is missing authentication steps in order for the fetch to work, even though fetchWithAuth in the Wix CLI is supposed to do the authentication.
//I tried both using the Wix Client method and creating a new API to fetch the InstanceID and use it here for further authentication, but neither of those options worked,
//and the deadline to submit was approaching so I decided to leave as is. The packaging fee currently always defaults to 10.


import { additionalFees } from "@wix/ecom/service-plugins";
import { httpClient, auth } from "@wix/essentials";
//import { createClient, ApiKeyStrategy } from "@wix/sdk";
//import dotenv from "dotenv";
//dotenv.config();

console.log("🚀 Plugin is starting...");

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
