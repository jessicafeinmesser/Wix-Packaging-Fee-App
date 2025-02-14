// import { auth } from "@wix/essentials";

// let packagingFee: number = 10; // Default packaging fee

// export async function GET(req: Request) {
//   try {
//     const instanceId = req.headers.get("Instance-ID");
//     if (!instanceId) {
//       return new Response(JSON.stringify({ error: "Missing instance ID" }), {
//         status: 400,
//         headers: { "Content-Type": "application/json" },
//       });
//     }

//     // Optional: Validate the instanceId if necessary
//     // For example, check if it matches a known pattern or exists in a database

//     const responsePayload = { fee: packagingFee };
//     console.log("GET response payload:", responsePayload);

//     return new Response(JSON.stringify(responsePayload), {
//       status: 200,
//       headers: { "Content-Type": "application/json" },
//     });
//   } catch (error) {
//     console.error("Error fetching packaging fee:", error);
//     return new Response(JSON.stringify({ error: (error as Error).message }), {
//       status: 500,
//       headers: { "Content-Type": "application/json" },
//     });
//   }
// }

// export async function POST(req: Request) {
//   try {
//     const instanceId = req.headers.get("Instance-ID");
//     if (!instanceId) {
//       return new Response(JSON.stringify({ error: "Missing instance ID" }), {
//         status: 400,
//         headers: { "Content-Type": "application/json" },
//       });
//     }

//     const { fee } = await req.json();
//     console.log("Incoming POST request body:", { fee });

//     if (typeof fee !== "number" || fee < 0) {
//       return new Response(JSON.stringify({ error: "Invalid fee value" }), {
//         status: 400,
//         headers: { "Content-Type": "application/json" },
//       });
//     }

//     packagingFee = fee; // Update the global fee
//     console.log("Updated packaging fee:", packagingFee);

//     const responsePayload = { fee: packagingFee };
//     console.log("POST response payload:", responsePayload);

//     return new Response(JSON.stringify(responsePayload), {
//       status: 200,
//       headers: { "Content-Type": "application/json" },
//     });
//   } catch (error) {
//     console.error("Error saving packaging fee:", error);
//     return new Response(JSON.stringify({ error: (error as Error).message }), {
//       status: 500,
//       headers: { "Content-Type": "application/json" },
//     });
//   }
// }

let packagingFee: number = 10; // Default packaging fee

export async function GET(req: Request) {
  try {
    const responsePayload = { fee: packagingFee };

    // Log the response structure before sending it
    console.log("GET response payload:", responsePayload);

    return new Response(JSON.stringify(responsePayload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Error fetching packaging fee:", error);
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

export async function POST(req: Request) {
  try {
    const { fee } = await req.json();

    // Log the incoming request body for debugging
    console.log("Incoming POST request body:", { fee });

    if (typeof fee !== "number" || fee < 0) {
      return new Response(JSON.stringify({ error: "Invalid fee value" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    packagingFee = fee; // Update the global fee
    console.log("Updated packaging fee:", packagingFee);

    const responsePayload = { fee: packagingFee };

    // Log the response structure before sending it
    console.log("POST response payload:", responsePayload);

    return new Response(JSON.stringify(responsePayload), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error("Error saving packaging fee:", error);
    return new Response(JSON.stringify({ error: (error as Error).message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
