import React, { useEffect, useState, FC } from "react";
import { httpClient } from "@wix/essentials";
import {
  Button,
  Input,
  Page,
  WixDesignSystemProvider,
} from "@wix/design-system";
import "@wix/design-system/styles.global.css";
import * as Icons from "@wix/wix-ui-icons-common";

// const Index: FC = () => {
//   const [currentFee, setCurrentFee] = useState<number>(10); // Store as number
//   const [newFee, setNewFee] = useState<string>("");

//   useEffect(() => {
//     // Function to get query parameters from the URL
//     function getQueryParam(param: string) {
//       const urlParams = new URLSearchParams(window.location.search);
//       return urlParams.get(param);
//     }

//     // Retrieve the 'instance' parameter
//     const instance = getQueryParam("instance");

//     if (instance) {
//       console.log("Instance parameter:", instance);

//       // Split the instance string into signature and data
//       const [signature, encodedData] = instance.split(".");

//       // Decode the base64-encoded data
//       const jsonData = atob(encodedData);
//       const instanceData = JSON.parse(jsonData);

//       // Extract the instanceId
//       const instanceId = instanceData.instanceId;
//       console.log("Instance ID:", instanceId);

//       // Fetch the packaging fee using the instanceId
//       const fetchPackagingFee = async () => {
//         try {
//           const response = await httpClient.fetchWithAuth(
//             `${import.meta.env.BASE_API_URL}/packaging-fee-api`,
//             {
//               method: "GET",
//               headers: {
//                 "Content-Type": "application/json",
//                 "Instance-ID": instanceId,
//               },
//             }
//           );
//           if (!response.ok)
//             throw new Error(`Failed to fetch: ${response.status}`);
//           const data = await response.json();
//           setCurrentFee(data.fee);
//         } catch (error) {
//           console.error("Error fetching packaging fee:", error);
//         }
//       };

//       fetchPackagingFee();
//     } else {
//       console.error("Instance parameter not found in the URL.");
//     }
//   }, []);

//   const handleFeeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
//     setNewFee(e.target.value);
//   };

//   const handleSaveFee = async () => {
//     try {
//       const response = await httpClient.fetchWithAuth(
//         `${import.meta.env.BASE_API_URL}/packaging-fee-api`,
//         {
//           method: "POST",
//           headers: {
//             "Content-Type": "application/json",
//           },
//           body: JSON.stringify({ fee: parseFloat(newFee) }),
//         }
//       );
//       if (response.ok) {
//         const data = await response.json();
//         setCurrentFee(data.fee);
//         setNewFee("");
//         alert("Packaging fee updated successfully!");
//       } else {
//         throw new Error("Failed to save packaging fee.");
//       }
//     } catch (error) {
//       console.error("Error saving packaging fee:", error);
//       alert("Error saving packaging fee.");
//     }
//   };

//   return (
//     <WixDesignSystemProvider features={{ newColorsBranding: true }}>
//       <Page>
//         <Page.Header
//           title="Packaging Fee Page"
//           subtitle="View and/or update your Packaging Fee."
//         />
//         <Page.Content>
//           <div style={{ padding: "20px" }}>
//             <h2>Current Packaging Fee: {currentFee}</h2>
//             <Input
//               value={newFee}
//               onChange={handleFeeChange}
//               placeholder="Enter new packaging fee"
//               required
//             />
//             <Button onClick={handleSaveFee} prefixIcon={<Icons.Edit />}>
//               Save New Fee
//             </Button>
//           </div>
//         </Page.Content>
//       </Page>
//     </WixDesignSystemProvider>
//   );
// };

// export default Index;

const Index: FC = () => {
  const [currentFee, setCurrentFee] = useState<number>(10); // Store as number
  const [newFee, setNewFee] = useState<string>("");

  useEffect(() => {
    const fetchPackagingFee = async () => {
      try {
        const response = await httpClient.fetchWithAuth(
          `${import.meta.env.BASE_API_URL}/packaging-fee-api`
        );
        if (!response.ok)
          throw new Error(`Failed to fetch: ${response.status}`);
        const data = await response.json();
        setCurrentFee(data.fee);
      } catch (error) {
        console.error("Error fetching packaging fee:", error);
      }
    };

    fetchPackagingFee();
  }, []);

  const handleFeeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setNewFee(e.target.value);
  };

  const handleSaveFee = async () => {
    try {
      const response = await httpClient.fetchWithAuth(
        `${import.meta.env.BASE_API_URL}/packaging-fee-api`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ fee: parseFloat(newFee) }),
        }
      );
      if (response.ok) {
        const data = await response.json();
        setCurrentFee(data.fee);
        setNewFee("");
        alert("Packaging fee updated successfully!");
      } else {
        throw new Error("Failed to save packaging fee.");
      }
    } catch (error) {
      console.error("Error saving packaging fee:", error);
      alert("Error saving packaging fee.");
    }
  };

  return (
    <WixDesignSystemProvider features={{ newColorsBranding: true }}>
      <Page>
        <Page.Header
          title="Packaging Fee Page"
          subtitle="View and/or update your Packaging Fee."
        />
        <Page.Content>
          <div style={{ padding: "20px" }}>
            <h2>Current Packaging Fee: {currentFee}</h2>
            <Input
              value={newFee}
              onChange={handleFeeChange}
              placeholder="Enter new packaging fee"
              required
            />
            <Button onClick={handleSaveFee} prefixIcon={<Icons.Edit />}>
              Save New Fee
            </Button>
          </div>
        </Page.Content>
      </Page>
    </WixDesignSystemProvider>
  );
};

export default Index;
