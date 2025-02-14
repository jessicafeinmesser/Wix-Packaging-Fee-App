//api.ts utilizes a global variable to store and update the packaging fee
// I ideally would have used the Wix Data API for stronger data persistence, but the import statements were causing countless errors, 
//so for the sake of simplicity and time I used a global variable.

let packagingFee: number = 10; // Default packaging fee

//fetch the packaging fee
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

//update the packaging fee
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
