let packagingFee = 10;
async function GET(req) {
  try {
    const responsePayload = { fee: packagingFee };
    console.log("GET response payload:", responsePayload);
    return new Response(JSON.stringify(responsePayload), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Error fetching packaging fee:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}
async function POST(req) {
  try {
    const { fee } = await req.json();
    console.log("Incoming POST request body:", { fee });
    if (typeof fee !== "number" || fee < 0) {
      return new Response(JSON.stringify({ error: "Invalid fee value" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    packagingFee = fee;
    console.log("Updated packaging fee:", packagingFee);
    const responsePayload = { fee: packagingFee };
    console.log("POST response payload:", responsePayload);
    return new Response(JSON.stringify(responsePayload), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (error) {
    console.error("Error saving packaging fee:", error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export { GET, POST };
//# sourceMappingURL=api.mjs.map
