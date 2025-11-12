import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# -------------------------------
# Create Stock Market Data
# -------------------------------
Data = {
    "Customer ID": ["C01", "C02", "C03", "C04", "C05", "C06", "C07"],
    "Date": ["1-11-2025", "2-11-2025", "3-11-2025", "4-11-2025", "5-11-2025", "6-11-2025", "7-11-2025"],
    "Stock Price": [100, 111, 101, 103, 104, 118, 106],
    "CP": [95, 98, 99, 100, 102, 104, 105],
    "SP": [100, 102, 101, 104, 107, 106, 108]
}

df = pd.DataFrame(Data)

# Calculate Profit/Loss and Daily Return
df["Profit/Loss"] = df["SP"] - df["CP"]
df["Daily_Return"] = df["SP"].pct_change() * 100

# -------------------------------
# Streamlit App Interface
# -------------------------------
st.title("📈 Stock Market Dashboard")
st.write("Analyze daily stock performance for each customer using pandas and Streamlit.")

# Input field for Customer ID
customer_id = st.text_input("Enter Customer ID (e.g., C01, C02, ...):")

if customer_id:
    if customer_id in df["Customer ID"].values:
        customer_data = df[df["Customer ID"] == customer_id]

        st.subheader(f"📊 Details for {customer_id}")
        st.dataframe(customer_data)

        # Show profit/loss details
        profit = float(customer_data["Profit/Loss"].values[0])
        daily_return = float(customer_data["Daily_Return"].fillna(0).values[0])

        st.write(f"**Profit/Loss:** ₹{profit}")
        st.write(f"**Daily Return:** {daily_return:.2f}%")

        # Plot Profit/Loss Trend
        fig, ax = plt.subplots()
        df.plot(x="Date", y="Profit/Loss", kind="line", marker="o", ax=ax)
        plt.title("Profit/Loss Trend Over Time")
        plt.xlabel("Date")
        plt.ylabel("Profit/Loss")
        st.pyplot(fig)

    else:
        st.error("❌ Customer ID not found! Please enter a valid one (like C01–C07).")

# Show full dataset (optional)
with st.expander("View Full Stock Data"):
    st.dataframe(df)


